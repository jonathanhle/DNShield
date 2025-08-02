// Package rules manages blocklist fetching and parsing from S3 for enterprise-wide
// rule management. It supports multiple blocklist formats (hosts files, domain lists)
// and provides automatic updates on a configurable schedule. Rules are fetched
// securely from S3 with support for IAM roles and credential management.
package rules

import (
	"context"
	"fmt"
	"os"
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

// Fetcher fetches rules from S3
type Fetcher struct {
	s3Client *s3.Client
	bucket   string
	key      string
}

// NewFetcher creates a new S3 rule fetcher
func NewFetcher(cfg *config.S3Config) (*Fetcher, error) {
	// Configure AWS SDK
	ctx := context.Background()

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
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(cfg.Region),
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	// Log credential source for transparency
	logrus.Infof("Using AWS credentials from: %s", creds.Source)

	return &Fetcher{
		s3Client: s3.NewFromConfig(awsCfg),
		bucket:   cfg.Bucket,
		key:      cfg.RulesPath,
	}, nil
}

// FetchRules fetches rules from S3
func (f *Fetcher) FetchRules() (*config.Rules, error) {
	if f.bucket == "" || f.key == "" {
		logrus.Warn("S3 bucket or key not configured, skipping rule fetch")
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get object from S3
	resp, err := f.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(f.bucket),
		Key:    aws.String(f.key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch rules from S3: %v", err)
	}
	defer resp.Body.Close()

	// Read response body with size limit
	data, err := utils.ReadAllLimited(resp.Body, utils.MaxRulesFileSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules: %v", err)
	}

	// Validate YAML before parsing
	if err := utils.SafeYAMLUnmarshal(data, nil, utils.MaxRulesFileSize); err != nil {
		return nil, fmt.Errorf("YAML validation failed: %v", err)
	}

	// Parse YAML
	var rules config.Rules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %v", err)
	}

	logrus.WithFields(logrus.Fields{
		"version": rules.Version,
		"domains": len(rules.Domains),
		"sources": len(rules.Sources),
	}).Info("Fetched rules from S3")

	return &rules, nil
}

// FetchRulesWithFallback fetches rules from S3 with local fallback
func (f *Fetcher) FetchRulesWithFallback(localPath string) (*config.Rules, error) {
	// Try S3 first
	rules, err := f.FetchRules()
	if err == nil && rules != nil {
		return rules, nil
	}

	if err != nil {
		logrus.WithError(err).Warn("Failed to fetch rules from S3, trying local fallback")
	}

	// Try local file
	if localPath != "" {
		// Check file size
		info, err := os.Stat(localPath)
		if err == nil && info.Size() <= utils.MaxRulesFileSize {
			data, err := os.ReadFile(localPath)
			if err == nil {
				// Validate YAML before parsing
				if err := utils.SafeYAMLUnmarshal(data, nil, utils.MaxRulesFileSize); err == nil {
					var localRules config.Rules
					if err := yaml.Unmarshal(data, &localRules); err == nil {
						logrus.Info("Using local rules file")
						return &localRules, nil
					}
				}
			}
		}
	}

	// Return empty rules if all else fails
	return &config.Rules{
		Version: "fallback",
		Updated: time.Now(),
	}, nil
}
