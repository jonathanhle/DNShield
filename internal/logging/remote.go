// Package logging provides remote logging capabilities for DNShield audit events.
// It supports sending logs to Splunk HEC and archiving to S3 with reliability features
// like buffering, retries, and local fallback.
package logging

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"dnshield/internal/audit"
	"dnshield/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"
)

// RemoteLogger handles sending logs to external systems
type RemoteLogger struct {
	splunkClient  *SplunkClient
	s3Client      *s3.Client
	s3Config      *config.S3Config
	buffer        *RingBuffer
	mu            sync.RWMutex
	shutdownCh    chan struct{}
	wg            sync.WaitGroup
}

// SplunkClient handles Splunk HEC communication
type SplunkClient struct {
	endpoint   string
	token      string
	index      string
	sourcetype string
	httpClient *http.Client
}

// SplunkEvent represents an event to send to Splunk
type SplunkEvent struct {
	Time       int64                  `json:"time"`
	Host       string                 `json:"host"`
	Source     string                 `json:"source"`
	Sourcetype string                 `json:"sourcetype"`
	Index      string                 `json:"index"`
	Event      map[string]interface{} `json:"event"`
}

// RingBuffer provides a thread-safe circular buffer for events
type RingBuffer struct {
	events    []audit.Event
	size      int
	head      int
	tail      int
	count     int
	mu        sync.Mutex
	notEmpty  sync.Cond
}

// NewRemoteLogger creates a new remote logger instance
func NewRemoteLogger(cfg *config.LoggingConfig, s3Client *s3.Client) (*RemoteLogger, error) {
	rl := &RemoteLogger{
		s3Client:   s3Client,
		shutdownCh: make(chan struct{}),
	}

	// Initialize buffer
	rl.buffer = NewRingBuffer(cfg.Local.BufferSize)

	// Initialize Splunk client if enabled
	if cfg.Splunk.Enabled {
		rl.splunkClient = &SplunkClient{
			endpoint:   cfg.Splunk.Endpoint,
			token:      cfg.Splunk.Token,
			index:      cfg.Splunk.Index,
			sourcetype: cfg.Splunk.Sourcetype,
			httpClient: &http.Client{
				Timeout: 10 * time.Second,
			},
		}
	}

	// Start background workers
	rl.wg.Add(2)
	go rl.splunkWorker()
	go rl.s3Worker()

	return rl, nil
}

// Log sends an audit event to remote systems
func (rl *RemoteLogger) Log(event audit.Event) {
	// Add to buffer for processing
	rl.buffer.Push(event)
}

// splunkWorker processes events from buffer and sends to Splunk
func (rl *RemoteLogger) splunkWorker() {
	defer rl.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	batch := make([]audit.Event, 0, 100)

	for {
		select {
		case <-rl.shutdownCh:
			// Send remaining events
			if len(batch) > 0 {
				rl.sendToSplunk(batch)
			}
			return

		case <-ticker.C:
			// Collect events from buffer
			for i := 0; i < 100; i++ {
				event, ok := rl.buffer.Pop()
				if !ok {
					break
				}
				batch = append(batch, event)
			}

			// Send batch if we have events
			if len(batch) > 0 {
				rl.sendToSplunk(batch)
				batch = batch[:0] // Reset slice
			}
		}
	}
}

// sendToSplunk sends a batch of events to Splunk HEC
func (rl *RemoteLogger) sendToSplunk(events []audit.Event) {
	if rl.splunkClient == nil {
		return
	}

	hostname, _ := getHostname()

	// Convert to Splunk format
	var payload bytes.Buffer
	for _, event := range events {
		splunkEvent := SplunkEvent{
			Time:       event.Timestamp.Unix(),
			Host:       hostname,
			Source:     "dnshield",
			Sourcetype: rl.splunkClient.sourcetype,
			Index:      rl.splunkClient.index,
			Event: map[string]interface{}{
				"event_type":   event.Type,
				"severity":     event.Severity,
				"message":      event.Message,
				"details":      event.Details,
				"user":         event.User,
				"process_id":   event.ProcessID,
				"process_name": event.ProcessName,
			},
		}

		jsonData, err := json.Marshal(splunkEvent)
		if err != nil {
			logrus.WithError(err).Error("Failed to marshal Splunk event")
			continue
		}
		payload.Write(jsonData)
		payload.WriteByte('\n')
	}

	// Send to Splunk with retries
	for attempt := 0; attempt < 3; attempt++ {
		if err := rl.splunkClient.send(payload.Bytes()); err != nil {
			logrus.WithError(err).Warnf("Failed to send to Splunk (attempt %d/3)", attempt+1)
			time.Sleep(time.Duration(attempt+1) * 5 * time.Second)
			continue
		}
		break
	}
}

// send performs the HTTP request to Splunk HEC
func (sc *SplunkClient) send(payload []byte) error {
	req, err := http.NewRequest("POST", sc.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Splunk %s", sc.token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("splunk returned status %d", resp.StatusCode)
	}

	return nil
}

// s3Worker handles periodic uploads to S3
func (rl *RemoteLogger) s3Worker() {
	defer rl.wg.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-rl.shutdownCh:
			// Final upload
			rl.uploadToS3()
			return

		case <-ticker.C:
			rl.uploadToS3()
		}
	}
}

// uploadToS3 uploads buffered events to S3
func (rl *RemoteLogger) uploadToS3() {
	if rl.s3Client == nil || rl.s3Config == nil {
		return
	}

	// Collect events for upload
	events := make([]audit.Event, 0, 1000)
	for i := 0; i < 1000; i++ {
		event, ok := rl.buffer.Pop()
		if !ok {
			break
		}
		events = append(events, event)
	}

	if len(events) == 0 {
		return
	}

	// Prepare compressed JSON
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	encoder := json.NewEncoder(gw)

	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			logrus.WithError(err).Error("Failed to encode event for S3")
		}
	}

	if err := gw.Close(); err != nil {
		logrus.WithError(err).Error("Failed to compress events for S3")
		return
	}

	// Upload to S3
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	key := fmt.Sprintf("%saudit-%s-%s.json.gz",
		rl.s3Config.LogPrefix,
		getHostname(),
		time.Now().UTC().Format("20060102-150405"))

	_, err := rl.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          aws.String(rl.s3Config.Bucket),
		Key:             aws.String(key),
		Body:            bytes.NewReader(buf.Bytes()),
		ContentType:     aws.String("application/gzip"),
		ContentEncoding: aws.String("gzip"),
	})

	if err != nil {
		logrus.WithError(err).Error("Failed to upload audit logs to S3")
		// Put events back in buffer
		for _, event := range events {
			rl.buffer.Push(event)
		}
	} else {
		logrus.WithField("count", len(events)).Info("Uploaded audit logs to S3")
	}
}

// Shutdown gracefully stops the remote logger
func (rl *RemoteLogger) Shutdown() error {
	close(rl.shutdownCh)
	rl.wg.Wait()
	return nil
}

// NewRingBuffer creates a new ring buffer
func NewRingBuffer(size int) *RingBuffer {
	rb := &RingBuffer{
		events: make([]audit.Event, size),
		size:   size,
	}
	rb.notEmpty.L = &rb.mu
	return rb
}

// Push adds an event to the buffer
func (rb *RingBuffer) Push(event audit.Event) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.events[rb.head] = event
	rb.head = (rb.head + 1) % rb.size

	if rb.count < rb.size {
		rb.count++
	} else {
		// Buffer full, overwrite oldest
		rb.tail = (rb.tail + 1) % rb.size
	}

	rb.notEmpty.Signal()
}

// Pop removes and returns an event from the buffer
func (rb *RingBuffer) Pop() (audit.Event, bool) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.count == 0 {
		return audit.Event{}, false
	}

	event := rb.events[rb.tail]
	rb.tail = (rb.tail + 1) % rb.size
	rb.count--

	return event, true
}

// getHostname returns the system hostname
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}