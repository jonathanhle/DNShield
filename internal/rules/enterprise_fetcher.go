package rules

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"dnshield/internal/config"
	"dnshield/internal/utils"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// EnterpriseFetcher fetches rules from S3 with multi-file support and ETag caching
type EnterpriseFetcher struct {
	s3Client  *s3.Client
	bucket    string
	paths     config.S3Paths
	etagCache map[string]string // Track ETags to avoid unnecessary downloads
	mu        sync.RWMutex
}

// NewEnterpriseFetcher creates a new enterprise rule fetcher
func NewEnterpriseFetcher(cfg *config.S3Config) (*EnterpriseFetcher, error) {
	// Configure AWS SDK with timeout for faster failure on non-EC2 systems
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get credentials securely
	creds, err := config.GetAWSCredentials(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS credentials: %v", err)
	}

	var awsCfg aws.Config

	// Configure based on credential source
	switch creds.Source {
	case config.CredentialSourceEnvironment, config.CredentialSourceConfig:
		// Use explicit credentials (from env or config)
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(cfg.Region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				creds.AccessKeyID,
				creds.SecretAccessKey,
				"",
			)),
		)
	default:
		// Use default credential chain (IAM role, etc.)
		// Use context timeout to avoid long waits on non-EC2 systems
		// Disable EC2 IMDS to avoid long timeouts on non-EC2 systems
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(cfg.Region),
			awsconfig.WithEC2IMDSEndpointMode(aws.EC2IMDSEndpointModeStateDisabled),
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	// Log credential source for transparency
	logrus.Infof("Using AWS credentials from: %s", creds.Source)

	return &EnterpriseFetcher{
		s3Client:  s3.NewFromConfig(awsCfg),
		bucket:    cfg.Bucket,
		paths:     cfg.Paths,
		etagCache: make(map[string]string),
	}, nil
}

// FetchResult contains the result of fetching a file
type FetchResult struct {
	Key     string
	Content []byte
	ETag    string
	Error   error
}

// fetchFile fetches a single file from S3, checking ETag for changes
func (f *EnterpriseFetcher) fetchFile(ctx context.Context, key string) FetchResult {
	// Check if we have a cached ETag
	f.mu.RLock()
	cachedETag := f.etagCache[key]
	f.mu.RUnlock()

	// First, do a HEAD request to check ETag
	headResp, err := f.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(f.bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		// File might not exist, which is OK for optional files
		return FetchResult{Key: key, Error: err}
	}

	// If ETag matches cached version, skip download
	currentETag := aws.ToString(headResp.ETag)
	if cachedETag != "" && cachedETag == currentETag {
		logrus.WithField("key", key).Debug("File unchanged (ETag match), skipping download")
		return FetchResult{Key: key, ETag: currentETag, Content: nil}
	}

	// Download the file
	resp, err := f.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(f.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return FetchResult{Key: key, Error: err}
	}
	defer resp.Body.Close()

	// Check content length
	contentLength := aws.ToInt64(resp.ContentLength)
	if contentLength > utils.MaxS3ObjectSize {
		return FetchResult{Key: key, Error: fmt.Errorf("S3 object exceeds maximum size of %d bytes", utils.MaxS3ObjectSize)}
	}
	
	// Read content with size limit
	content, err := utils.ReadAllLimited(resp.Body, utils.MaxS3ObjectSize)
	if err != nil {
		return FetchResult{Key: key, Error: err}
	}

	// Update ETag cache
	f.mu.Lock()
	f.etagCache[key] = currentETag
	f.mu.Unlock()

	return FetchResult{
		Key:     key,
		Content: content,
		ETag:    currentETag,
	}
}

// GetDeviceName returns the device name for this machine
func GetDeviceName() string {
	// Try to get the ComputerName (user-friendly name)
	name, err := os.Hostname()
	if err != nil {
		logrus.WithError(err).Warn("Failed to get hostname")
		return "unknown"
	}

	// On macOS, we might want to use scutil for the actual computer name
	// For now, using hostname is sufficient
	return name
}

// FetchEnterpriseRules fetches all rules for the current device
func (f *EnterpriseFetcher) FetchEnterpriseRules() (*EnterpriseRules, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result := &EnterpriseRules{
		DeviceName: GetDeviceName(),
		FetchTime:  time.Now(),
	}

	// Step 1: Fetch device mapping
	deviceMappingResult := f.fetchFile(ctx, f.paths.DeviceMapping)
	if deviceMappingResult.Error != nil {
		return nil, fmt.Errorf("failed to fetch device mapping: %v", deviceMappingResult.Error)
	}

	if deviceMappingResult.Content != nil {
		// Validate YAML before parsing
		if err := utils.SafeYAMLUnmarshal(deviceMappingResult.Content, nil, utils.MaxRulesFileSize); err != nil {
			return nil, fmt.Errorf("device mapping YAML validation failed: %v", err)
		}
		
		var deviceMapping config.DeviceMapping
		if err := yaml.Unmarshal(deviceMappingResult.Content, &deviceMapping); err != nil {
			return nil, fmt.Errorf("failed to parse device mapping: %v", err)
		}

		// Find user for this device
		for user, devices := range deviceMapping.Users {
			for _, device := range devices.Devices {
				if device == result.DeviceName {
					result.UserEmail = user
					break
				}
			}
			if result.UserEmail != "" {
				break
			}
		}
	}

	if result.UserEmail == "" {
		logrus.WithField("device", result.DeviceName).Warn("Device not found in mapping, applying base rules only")
	}

	// Step 2: Fetch user groups (if we have a user)
	if result.UserEmail != "" {
		userGroupsResult := f.fetchFile(ctx, f.paths.UserGroups)
		if userGroupsResult.Error == nil && userGroupsResult.Content != nil {
			// Validate YAML before parsing
			if err := utils.SafeYAMLUnmarshal(userGroupsResult.Content, nil, utils.MaxRulesFileSize); err != nil {
				logrus.WithError(err).Warn("User groups YAML validation failed")
			} else {
				var userGroups config.UserGroups
				if err := yaml.Unmarshal(userGroupsResult.Content, &userGroups); err == nil {
				// Check direct override first
				if group, ok := userGroups.UserOverrides[result.UserEmail]; ok {
					result.GroupName = group
				} else {
					// Check group assignments
					for group, users := range userGroups.GroupAssignments {
						for _, user := range users {
							if user == result.UserEmail ||
								(strings.Contains(user, "*") && matchesWildcard(result.UserEmail, user)) {
								result.GroupName = group
								break
							}
						}
						if result.GroupName != "" {
							break
						}
					}
				}
				}
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"device": result.DeviceName,
		"user":   result.UserEmail,
		"group":  result.GroupName,
	}).Info("Resolved device identity")

	// Step 3: Fetch base rules (everyone gets these)
	baseResult := f.fetchFile(ctx, f.paths.Base)
	if baseResult.Error == nil && baseResult.Content != nil {
		// Validate YAML before parsing
		if err := utils.SafeYAMLUnmarshal(baseResult.Content, nil, utils.MaxRulesFileSize); err != nil {
			logrus.WithError(err).Warn("Base rules YAML validation failed")
		} else {
			var baseRules config.Rules
			if err := yaml.Unmarshal(baseResult.Content, &baseRules); err == nil {
			baseRules.Normalize()
				result.BaseRules = &baseRules
			}
		}
	}

	// Step 4: Fetch group rules (if applicable)
	if result.GroupName != "" {
		groupKey := path.Join(f.paths.GroupsDir, result.GroupName+".yaml")
		groupResult := f.fetchFile(ctx, groupKey)
		if groupResult.Error == nil && groupResult.Content != nil {
			// Validate YAML before parsing
			if err := utils.SafeYAMLUnmarshal(groupResult.Content, nil, utils.MaxRulesFileSize); err != nil {
				logrus.WithError(err).Warn("Group rules YAML validation failed")
			} else {
				var groupRules config.Rules
				if err := yaml.Unmarshal(groupResult.Content, &groupRules); err == nil {
				groupRules.Normalize()
					result.GroupRules = &groupRules
				}
			}
		}
	}

	// Step 5: Fetch user overrides (if applicable)
	if result.UserEmail != "" {
		overrideKey := path.Join(f.paths.UserOverridesDir, result.UserEmail+".yaml")
		overrideResult := f.fetchFile(ctx, overrideKey)
		if overrideResult.Error == nil && overrideResult.Content != nil {
			// Validate YAML before parsing
			if err := utils.SafeYAMLUnmarshal(overrideResult.Content, nil, utils.MaxRulesFileSize); err != nil {
				logrus.WithError(err).Warn("User override rules YAML validation failed")
			} else {
				var userRules config.Rules
				if err := yaml.Unmarshal(overrideResult.Content, &userRules); err == nil {
				userRules.Normalize()
					result.UserRules = &userRules
				}
			}
		}
	}

	return result, nil
}

// matchesWildcard checks if an email matches a wildcard pattern
func matchesWildcard(email, pattern string) bool {
	// Simple wildcard matching for patterns like *@domain.com
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(email, suffix)
	}
	return email == pattern
}

// EnterpriseRules contains all rules applicable to a device
type EnterpriseRules struct {
	DeviceName string
	UserEmail  string
	GroupName  string
	BaseRules  *config.Rules
	GroupRules *config.Rules
	UserRules  *config.Rules
	FetchTime  time.Time
}

// IsAllowOnlyMode checks if allow-only mode is enabled for this device
// Priority: User > Group > Base (if any level has it enabled, it's enabled)
func (er *EnterpriseRules) IsAllowOnlyMode() bool {
	// Check user rules first (highest priority)
	if er.UserRules != nil && er.UserRules.AllowOnlyMode {
		return true
	}

	// Check group rules
	if er.GroupRules != nil && er.GroupRules.AllowOnlyMode {
		return true
	}

	// Check base rules
	if er.BaseRules != nil && er.BaseRules.AllowOnlyMode {
		return true
	}

	return false
}

// MergeRules merges all rules according to precedence
func (er *EnterpriseRules) MergeRules() (blockDomains []string, allowDomains []string, allowOnlyMode bool) {
	blockMap := make(map[string]bool)
	allowMap := make(map[string]bool)

	// Check if allow-only mode is enabled
	allowOnlyMode = er.IsAllowOnlyMode()

	// Start with base rules
	if er.BaseRules != nil {
		for _, domain := range er.BaseRules.BlockDomains {
			blockMap[strings.ToLower(domain)] = true
		}
		for _, domain := range er.BaseRules.AllowDomains {
			allowMap[strings.ToLower(domain)] = true
		}
	}

	// Add group rules
	if er.GroupRules != nil {
		for _, domain := range er.GroupRules.BlockDomains {
			blockMap[strings.ToLower(domain)] = true
		}
		for _, domain := range er.GroupRules.AllowDomains {
			allowMap[strings.ToLower(domain)] = true
		}
	}

	// Add user rules (highest precedence)
	if er.UserRules != nil {
		for _, domain := range er.UserRules.BlockDomains {
			blockMap[strings.ToLower(domain)] = true
		}
		for _, domain := range er.UserRules.AllowDomains {
			allowMap[strings.ToLower(domain)] = true
		}
	}

	// Convert maps to slices
	for domain := range blockMap {
		blockDomains = append(blockDomains, domain)
	}
	for domain := range allowMap {
		allowDomains = append(allowDomains, domain)
	}

	return blockDomains, allowDomains, allowOnlyMode
}

// GetBlockSources returns all external blocklist URLs to fetch
func (er *EnterpriseRules) GetBlockSources() []string {
	sourceMap := make(map[string]bool)

	if er.BaseRules != nil {
		for _, source := range er.BaseRules.BlockSources {
			sourceMap[source] = true
		}
	}

	if er.GroupRules != nil {
		for _, source := range er.GroupRules.BlockSources {
			sourceMap[source] = true
		}
	}

	if er.UserRules != nil {
		for _, source := range er.UserRules.BlockSources {
			sourceMap[source] = true
		}
	}

	var sources []string
	for source := range sourceMap {
		sources = append(sources, source)
	}

	return sources
}
