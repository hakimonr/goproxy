package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Apply rate limiting if target matches scope
	if p.shouldThrottle(r.URL.Host) {
		p.applyRateLimit()
	}

	// Read request body for logging
	var reqBody []byte
	if r.Body != nil && p.LogRequestBody {
		// Check if this content should be logged based on content type and file extension
		contentType := r.Header.Get("Content-Type")
		if p.shouldLogContent(contentType, r.URL.Path) {
			// Only log text-based content and limit size to prevent huge logs
			// Read a prefix of the body for logging without consuming the whole stream
			limitReader := io.LimitReader(r.Body, p.MaxLogBodySize)
			var err error
			reqBody, err = io.ReadAll(limitReader)
			if err != nil {
				log.Printf("[ERROR] Failed to read request body: %v", err)
			}

			// Restore the body for the actual request by combining prefix and remaining body
			// valid because limitReader read from r.Body, advancing it
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(reqBody), r.Body))

			if len(reqBody) > 0 {
				// Check if content is likely text before logging
				if !p.isTextContent(contentType, reqBody) {
					log.Printf("[INFO] Request body: [%d bytes of binary content not logged]", len(reqBody))
					// We keep reqBody for potential structured logging, but might want to clear it if huge?
					// For now, keeping it as is consistent with previous logic, just ensuring we don't lose data for forwarding.
				} else if int64(len(reqBody)) == p.MaxLogBodySize {
					log.Printf("[INFO] Request body: [truncated - first %d bytes logged]", p.MaxLogBodySize)
				}
			}
		} else {
			log.Printf("[INFO] Request body: [content type or extension excluded from logging]")
		}
	}

	// Create a new request to forward to the target
	// The original request has RequestURI set which is not allowed for client requests
	newReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		log.Printf("[ERROR] Failed to create new request: %v", err)
		if p.Logger != nil {
			p.Logger.LogRequestResponse(r, nil, reqBody, nil, startTime, err)
		}
		return
	}

	// Copy headers from the original request
	for key, values := range r.Header {
		for _, value := range values {
			newReq.Header.Add(key, value)
		}
	}

	// Forward request to target using reusable client
	resp, err := p.HTTPClient.Do(newReq)
	if err != nil {
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		log.Printf("[ERROR] Failed to forward request: %v", err)
		if p.Logger != nil {
			p.Logger.LogRequestResponse(r, nil, reqBody, nil, startTime, err)
		}
		return
	}

	// Check if the response is valid before proceeding
	if resp.StatusCode < 100 || resp.StatusCode > 599 {
		resp.Body.Close()
		http.Error(w, "Invalid response from target server", http.StatusBadGateway)
		log.Printf("[ERROR] Invalid response status code: %d", resp.StatusCode)
		if p.Logger != nil {
			p.Logger.LogRequestResponse(r, nil, reqBody, nil, startTime, fmt.Errorf("invalid response status code: %d", resp.StatusCode))
		}
		return
	}

	defer resp.Body.Close()

	// Read response body to log it
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read response body: %v", err)
		// Don't return an error to client, just log it and continue with empty body
		respBody = []byte{}
	}

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	// Write response body back to client
	_, err = w.Write(respBody)
	if err != nil {
		log.Printf("[ERROR] Failed to write response body: %v", err)
	}


	// Log the request/response pair using the enhanced logger
	if p.Logger != nil {
		if p.StructuredLogging {
			p.Logger.LogRequestResponse(r, resp, reqBody, respBody, startTime, nil)
		} else {
			p.Logger.LogBurpFormat(r, resp, reqBody, respBody, startTime, nil)
		}
	} else {
		// Fallback to the previous logging method
		p.logDetailed("[→] %s %s %s", r.Method, r.URL.String(), r.Proto)
		if p.LogRequestHeaders {
			p.logDetailed("    Headers: %v", r.Header)
		}
		if len(reqBody) > 0 && p.LogRequestBody {
			p.logDetailed("    Body: %s", string(reqBody))
		}

		p.logDetailed("[←] %s %s %d", r.Method, r.URL.String(), resp.StatusCode)
		if p.LogResponseHeaders {
			p.logDetailed("    Response Headers: %v", resp.Header)
		}
		if len(respBody) > 0 && p.LogResponseBody {
			// Check if this content should be logged based on content type and file extension
			contentType := resp.Header.Get("Content-Type")
			if p.shouldLogContent(contentType, r.URL.Path) {
				// Check if content is likely text before logging
				if p.isTextContent(contentType, respBody) {
					p.logDetailed("    Response Body: %s", string(respBody))
				} else {
					p.logDetailed("    Response Body: [%d bytes of binary content not logged]", len(respBody))
				}
			} else {
				p.logDetailed("    Response Body: [content type or extension excluded from logging]")
			}
		}
	}
}

func (p *ProxyServer) shouldThrottle(host string) bool {
	if p.TargetScope == nil {
		return true // Apply to all if no scope defined
	}
	return p.TargetScope.MatchString(host)
}

func (p *ProxyServer) applyRateLimit() {
	// Use the enhanced rate limiting with mode support
	p.applyRateLimitWithMode()
}