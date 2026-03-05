package output

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/projectdiscovery/gologger"
)

// AsyncOutputCoordinator manages async writing of scan results to disk
type AsyncOutputCoordinator struct {
	outputChan  chan []byte
	file        *os.File
	writer      *bufio.Writer
	shutdownCtx context.Context
	cancel      context.CancelFunc
	flushTicker *time.Ticker
	done        chan struct{}
}

// NewAsyncOutputCoordinator creates a new coordinator with proper validation
func NewAsyncOutputCoordinator(filename string, bufferSize int, flushInterval time.Duration) (*AsyncOutputCoordinator, error) {
	// Validate input parameters
	if bufferSize <= 0 {
		return nil, fmt.Errorf("buffer size must be greater than 0")
	}
	if flushInterval <= 0 {
		return nil, fmt.Errorf("flush interval must be greater than 0")
	}

	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	coord := &AsyncOutputCoordinator{
		outputChan:  make(chan []byte, bufferSize),
		file:        file,
		writer:      bufio.NewWriter(file),
		shutdownCtx: ctx,
		cancel:      cancel,
		flushTicker: time.NewTicker(flushInterval),
		done:        make(chan struct{}),
	}

	go coord.writeLoop()
	return coord, nil
}

// writeLoop handles writing to disk with proper channel draining
func (c *AsyncOutputCoordinator) writeLoop() {
	defer func() {
		c.flushTicker.Stop()
		if err := c.writer.Flush(); err != nil {
			gologger.Error().Msgf("Failed to flush writer during shutdown: %v", err)
		}
		close(c.done)
	}()

	// Use range to ensure all data is processed before channel closes
	for data := range c.outputChan {
		if _, err := c.writer.Write(data); err != nil {
			gologger.Error().Msgf("Failed to write data: %v", err)
			// Don't continue silently - we want to know about write failures
		}
	}

	// Final flush when channel is closed
	if err := c.writer.Flush(); err != nil {
		gologger.Error().Msgf("Failed to flush writer during shutdown: %v", err)
	}
}

// Submit sends a result to the coordinator
func (c *AsyncOutputCoordinator) Submit(result interface{}) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}
	data = append(data, '\n')

	select {
	case c.outputChan <- data:
		return nil
	case <-c.shutdownCtx.Done():
		return fmt.Errorf("coordinator is shutting down")
	}
}

// GracefulShutdown closes the channel and waits for completion
func (c *AsyncOutputCoordinator) GracefulShutdown() error {
	c.cancel()          // Stop accepting new submissions
	close(c.outputChan) // Close channel to unblock writeLoop
	<-c.done            // Wait for writeLoop to complete
	return c.file.Close()
}

// HandleSignals sets up signal handling for graceful shutdown
func (c *AsyncOutputCoordinator) HandleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		gologger.Info().Msg("Received interrupt signal. Shutting down gracefully...")
		if err := c.GracefulShutdown(); err != nil {
			gologger.Error().Msgf("Shutdown error: %v", err)
		}
	}()
}
