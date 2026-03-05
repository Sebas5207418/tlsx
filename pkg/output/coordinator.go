package output

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/projectdiscovery/gologger"
)

// AsyncOutputCoordinator manages async writing of scan results to disk.
// Uses buffered channel for concurrent submission and periodic flushing.
type AsyncOutputCoordinator struct {
	outputChan  chan []byte
	file        *os.File
	writer      *bufio.Writer
	shutdownCtx context.Context
	cancel      context.CancelFunc
	flushTicker *time.Ticker
	done        chan struct{}
}

// NewAsyncOutputCoordinator creates a new coordinator.
// bufferSize: Size of the buffered channel (e.g., 10000 for 10k pending results).
// flushInterval: How often to flush the buffer to disk (e.g., 1*time.Second).
func NewAsyncOutputCoordinator(filename string, bufferSize int, flushInterval time.Duration) (*AsyncOutputCoordinator, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	coord := &AsyncOutputCoordinator{
		outputChan:  make(chan []byte, bufferSize),
		file:        file,
		writer:      bufio.NewWriter(file),
		shutdownCtx: ctx,
		cancel:      cancel,
		flushTicker:  time.NewTicker(flushInterval),
		done:        make(chan struct{}),
	}

	go coord.writeLoop()
	return coord, nil
}

// writeLoop is the dedicated goroutine for writing to disk.
// Uses periodic flushing instead of flushing after every write.
func (c *AsyncOutputCoordinator) writeLoop() {
	defer func() {
		c.flushTicker.Stop()
		close(c.done)
	}()

	for {
		select {
		case data, ok := <-c.outputChan:
			if !ok {
				// Channel closed, drain remaining data
				if err := c.writer.Flush(); err != nil {
					gologger.Warning().Msgf("Failed to flush writer during shutdown: %v", err)
				}
				return
			}
			if _, err := c.writer.Write(data); err != nil {
				gologger.Warning().Msgf("Failed to write data: %v", err)
				continue
			}

		case <-c.flushTicker.C:
			if err := c.writer.Flush(); err != nil {
				gologger.Warning().Msgf("Failed to flush writer: %v", err)
			}

		case <-c.shutdownCtx.Done():
			// Drain the channel before exiting
			for {
				select {
				case data, ok := <-c.outputChan:
					if !ok {
						if err := c.writer.Flush(); err != nil {
							gologger.Warning().Msgf("Failed to flush writer during shutdown: %v", err)
						}
						return
					}
					if _, err := c.writer.Write(data); err != nil {
						gologger.Warning().Msgf("Failed to write data during shutdown: %v", err)
						continue
					}
				default:
					if err := c.writer.Flush(); err != nil {
						gologger.Warning().Msgf("Failed to flush writer during shutdown: %v", err)
					}
					return
				}
			}
		}
	}
}

// Submit sends a result to the coordinator.
// Returns an error if the coordinator is shutting down.
func (c *AsyncOutputCoordinator) Submit(result interface{}) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	select {
	case c.outputChan <- data:
		return nil
	case <-c.shutdownCtx.Done():
		return context.Canceled
	}
}

// GracefulShutdown waits for all data to be written and closes the file.
// Call this when the scan is complete or on program exit.
func (c *AsyncOutputCoordinator) GracefulShutdown() error {
	c.cancel()
	<-c.done
	return c.file.Close()
}

// HandleSignals sets up signal handling for graceful shutdown on CTRL+C.
// Does not call os.Exit(), allowing defer statements to execute.
func (c *AsyncOutputCoordinator) HandleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		gologger.Info().Msg("Received interrupt signal. Shutting down gracefully...")
		c.GracefulShutdown()
	}()
}
