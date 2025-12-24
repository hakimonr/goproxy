package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"
)

// LogEntry represents a single log entry with request/response pair
type LogEntry struct {
	ID               string                 `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	Method           string                 `json:"method"`
	URL              string                 `json:"url"`
	Protocol         string                 `json:"protocol"`
	StatusCode       int                    `json:"status_code,omitempty"`
	RequestHeaders   map[string][]string    `json:"request_headers"`
	RequestBody      string                 `json:"request_body,omitempty"`
	ResponseHeaders  map[string][]string    `json:"response_headers,omitempty"`
	ResponseBody     string                 `json:"response_body,omitempty"`
	RequestSize      int64                  `json:"request_size"`
	ResponseSize     int64                  `json:"response_size,omitempty"`
	ElapsedTime      time.Duration          `json:"elapsed_time"`
	ContentType      string                 `json:"content_type,omitempty"`
	RemoteAddr       string                 `json:"remote_addr,omitempty"`
	Error            string                 `json:"error,omitempty"`
	CustomFields     map[string]interface{} `json:"custom_fields,omitempty"`
}

// Logger handles structured logging for HTTP/HTTPS traffic
type Logger struct {
	file       *os.File
	writer     *bufio.Writer
	enabled    bool
	maxSize    int64
	currentSize int64
	logDir     string
	logFile    string
}

// NewLogger creates a new logger instance
func NewLogger(logFile string, maxSize int64) (*Logger, error) {
	logger := &Logger{
		enabled: true,
		maxSize: maxSize * 1024 * 1024, // Convert MB to bytes
		logDir:  "log",
		logFile: logFile,
	}

	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logger.logDir, 0755); err != nil {
		return nil, err
	}

	// Open log file
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	logger.file = file
	logger.writer = bufio.NewWriter(file)

	// Get initial file size
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	logger.currentSize = stat.Size()

	return logger, nil
}

// LogRequestResponse logs a complete request-response pair
func (l *Logger) LogRequestResponse(req *http.Request, resp *http.Response, reqBody, respBody []byte, startTime time.Time, err error) error {
	if !l.enabled {
		return nil
	}

	// Create log entry
	entry := &LogEntry{
		ID:             fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp:      time.Now(),
		Method:         req.Method,
		URL:            req.URL.String(),
		Protocol:       req.Proto,
		RequestHeaders: req.Header,
		RequestSize:    int64(len(reqBody)),
		RemoteAddr:     req.RemoteAddr,
		CustomFields:   make(map[string]interface{}),
	}

	// Add request body if not too large and is text content
	if len(reqBody) > 0 && l.isTextContent(req.Header.Get("Content-Type"), reqBody) {
		entry.RequestBody = string(reqBody)
	} else if len(reqBody) > 0 {
		entry.RequestSize = int64(len(reqBody))
	}

	// Add response data if available
	if resp != nil {
		entry.StatusCode = resp.StatusCode
		entry.ResponseHeaders = resp.Header

		// Add response body if not too large and is text content
		if len(respBody) > 0 && l.isTextContent(resp.Header.Get("Content-Type"), respBody) {
			entry.ResponseBody = string(respBody)
		} else if len(respBody) > 0 {
			entry.ResponseSize = int64(len(respBody))
		}

		// Get content type from header
		entry.ContentType = resp.Header.Get("Content-Type")

		// Calculate response size
		if resp.Body != nil {
			entry.ResponseSize = int64(len(respBody))
		}
	}

	// Calculate elapsed time
	entry.ElapsedTime = time.Since(startTime)

	// Add error if present
	if err != nil {
		entry.Error = err.Error()
	}

	// Convert to JSON
	jsonData, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Check if adding this data would exceed the max size
	if l.currentSize+int64(len(jsonData)) > l.maxSize {
		if err := l.rotate(); err != nil {
			return err
		}
	}

	// Write to file
	_, err = l.writer.Write(append(jsonData, '\n'))
	if err != nil {
		return err
	}

	// Update current size
	l.currentSize += int64(len(jsonData)) + 1

	return nil
}

// LogBurpFormat logs request/response in Burp Suite compatible format
func (l *Logger) LogBurpFormat(req *http.Request, resp *http.Response, reqBody, respBody []byte, startTime time.Time, err error) error {
	if !l.enabled {
		return nil
	}

	var output strings.Builder

	// Format request
	reqDump, err := httputil.DumpRequestOut(req, false) // Don't include body in dump to avoid corruption
	if err != nil {
		return err
	}

	output.WriteString(fmt.Sprintf("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n"))
	output.WriteString(fmt.Sprintf("Request Time: %s\n", startTime.Format(time.RFC3339)))
	if req.URL.Scheme == "https" {
		output.WriteString(fmt.Sprintf("Type: HTTPS CONNECT\n"))
	} else {
		output.WriteString(fmt.Sprintf("Method: %s\n", req.Method))
		output.WriteString(fmt.Sprintf("URL: %s\n", req.URL.String()))
	}
	output.WriteString(fmt.Sprintf("Protocol: %s\n", req.Proto))
	output.WriteString(fmt.Sprintf("Request Headers:\n%s", string(reqDump)))
	if len(reqBody) > 0 && l.isTextContent(req.Header.Get("Content-Type"), reqBody) {
		output.WriteString(fmt.Sprintf("Request Body:\n%s\n", string(reqBody)))
	} else if len(reqBody) > 0 {
		output.WriteString(fmt.Sprintf("Request Body: [%d bytes of binary content not logged]\n", len(reqBody)))
	}

	// Add response if available
	if resp != nil {
		output.WriteString(fmt.Sprintf("\nResponse Status: %d %s\n", resp.StatusCode, resp.Status))
		output.WriteString(fmt.Sprintf("Response Headers:\n"))
		for name, values := range resp.Header {
			for _, value := range values {
				output.WriteString(fmt.Sprintf("%s: %s\n", name, value))
			}
		}
		if len(respBody) > 0 && l.isTextContent(resp.Header.Get("Content-Type"), respBody) {
			output.WriteString(fmt.Sprintf("Response Body:\n%s\n", string(respBody)))
		} else if len(respBody) > 0 {
			output.WriteString(fmt.Sprintf("Response Body: [%d bytes of binary content not logged]\n", len(respBody)))
		}
	} else if err != nil {
		output.WriteString(fmt.Sprintf("Error: %s\n", err.Error()))
	}

	// Calculate and add elapsed time
	elapsed := time.Since(startTime)
	output.WriteString(fmt.Sprintf("\nElapsed Time: %s\n", elapsed.String()))

	output.WriteString(fmt.Sprintf("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=\n\n"))

	// Check if adding this data would exceed the max size
	content := output.String()
	if l.currentSize+int64(len(content)) > l.maxSize {
		if err := l.rotate(); err != nil {
			return err
		}
	}

	// Write to file
	_, err = l.writer.WriteString(content)
	if err != nil {
		return err
	}

	// Update current size
	l.currentSize += int64(len(content))

	return nil
}

// isTextContent checks if the content is likely to be text based on content-type and content itself
func (l *Logger) isTextContent(contentType string, content []byte) bool {
	// Check Content-Type header
	if contentType != "" {
		// Common text content types
		textTypes := []string{"text/", "application/json", "application/xml", "application/x-www-form-urlencoded", "application/javascript", "application/ecmascript", "multipart/form-data", "application/x-www-form-urlencoded"}
		for _, textType := range textTypes {
			if strings.Contains(strings.ToLower(contentType), textType) {
				return true
			}
		}

		// Explicitly exclude binary content types
		binaryTypes := []string{"application/octet-stream", "application/zip", "application/x-zip",
			"application/gzip", "application/x-gzip", "application/x-tar", "application/x-rar-compressed",
			"application/pdf", "application/msword", "application/vnd.ms-excel",
			"application/vnd.openxmlformats-officedocument", "image/", "video/", "audio/",
			"application/x-shockwave-flash", "application/font", "font/"}
		for _, binaryType := range binaryTypes {
			if strings.Contains(strings.ToLower(contentType), binaryType) {
				return false
			}
		}
	}

	// Check for common binary file signatures (magic bytes)
	if l.hasBinarySignature(content) {
		return false
	}

	// Even if Content-Type isn't text, check if the content looks like text
	// Check the first 1000 bytes to see if it's mostly printable characters
	checkLen := len(content)
	if checkLen > 1000 {
		checkLen = 1000
	}

	textChars := 0
	nullByteCount := 0
	for i := 0; i < checkLen; i++ {
		b := content[i]
		// Count null bytes which are common in binary files
		if b == 0 {
			nullByteCount++
		}
		// Printable ASCII characters, tab, newline, carriage return
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			textChars++
		}
	}

	// If more than 10% of the content consists of null bytes, it's likely binary
	if float64(nullByteCount)/float64(checkLen) > 0.1 {
		return false
	}

	// If more than 80% of the content looks like text, consider it text
	return float64(textChars)/float64(checkLen) > 0.8
}

// hasBinarySignature checks for common binary file signatures (magic bytes)
func (l *Logger) hasBinarySignature(content []byte) bool {
	if len(content) < 4 {
		return false
	}

	// Common binary file signatures
	signatures := [][]byte{
		{0x1f, 0x8b},                   // gzip
		{0x50, 0x4b},                   // zip
		{0x52, 0x61, 0x72, 0x21},      // rar
		{0x25, 0x50, 0x44, 0x46},      // pdf
		{0x89, 0x50, 0x4e, 0x47},      // png
		{0xff, 0xd8, 0xff},             // jpg
		{0x47, 0x49, 0x46},             // gif
		{0x42, 0x4d},                   // bmp
		{0x49, 0x49, 0x2a, 0x00},      // tiff (little endian)
		{0x4d, 0x4d, 0x00, 0x2a},      // tiff (big endian)
		{0x49, 0x44, 0x33},             // mp3
		{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, // mp4
		{0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70}, // mp4
		{0x52, 0x49, 0x46, 0x46},      // webp, wav
		{0x4f, 0x67, 0x67, 0x53},      // ogg
	}

	for _, sig := range signatures {
		if len(content) >= len(sig) {
			match := true
			for i, b := range sig {
				if content[i] != b {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}

	return false
}

// rotate handles log file rotation when size limit is reached
func (l *Logger) rotate() error {
	// Flush current buffer
	if err := l.writer.Flush(); err != nil {
		return err
	}

	// Close current file
	if err := l.file.Close(); err != nil {
		return err
	}

	// Create a new filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	baseName := strings.TrimSuffix(l.logFile, ".log")
	newFileName := fmt.Sprintf("%s_%s.log", baseName, timestamp)

	// Rename the current log file to the rotated name
	if err := os.Rename(l.logFile, newFileName); err != nil {
		return err
	}

	// Create a new log file
	file, err := os.OpenFile(l.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	l.file = file
	l.writer = bufio.NewWriter(file)
	l.currentSize = 0

	return nil
}

// Close closes the logger and its underlying file
func (l *Logger) Close() error {
	if l.writer != nil {
		if err := l.writer.Flush(); err != nil {
			return err
		}
	}
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// LogAsGoProxyFormat logs in the current go proxy format for compatibility
func (l *Logger) LogAsGoProxyFormat(format string, args ...interface{}) {
	if !l.enabled {
		return
	}

	logLine := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	output := fmt.Sprintf("%s %s\n", timestamp, logLine)

	// Check size before writing
	if l.currentSize+int64(len(output)) > l.maxSize {
		l.rotate()
	}

	l.writer.WriteString(output)
	l.currentSize += int64(len(output))
}

// GetLogSize returns the current size of the log file
func (l *Logger) GetLogSize() int64 {
	return l.currentSize
}

// GetLogPath returns the current log file path
func (l *Logger) GetLogPath() string {
	return l.logFile
}