package output

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
)

// AsyncOutputCoordinator manages async writing of scan results to disk.
// It uses a buffered channel for concurrent submission and a dedicated goroutine for writing.
// No mutexes are used; coordination is done via channels (Go-style).
type AsyncOutputCoordinator struct {
	outputChan  chan []byte
	file        *os.File
	writer      *bufio.Writer
	done        chan struct{}
	shutdownCtx context.Context
	cancel      context.CancelFunc
}

// NewAsyncOutputCoordinator creates a new coordinator.
// bufferSize: Size of the buffered channel (e.g., 10000 for 10k pending results).
func NewAsyncOutputCoordinator(filename string, bufferSize int) (*AsyncOutputCoordinator, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	coord := &AsyncOutputCoordinator{
		outputChan:  make(chan []byte, bufferSize),
		file:        file,
		writer:      bufio.NewWriter(file),
		done:        make(chan struct{}),
		shutdownCtx: ctx,
		cancel:      cancel,
	}

	// Start the writer goroutine
	go coord.writeLoop()
	return coord, nil
}

// writeLoop is the dedicated goroutine for writing to disk.
// It flushes after every write to prevent truncated output.
func (c *AsyncOutputCoordinator) writeLoop() {
	defer close(c.done)
	for {
		select {
		case data, ok := <-c.outputChan:
			if !ok {
				// Channel closed, flush and exit
				c.writer.Flush()
				return
			}
			if _, err := c.writer.Write(data); err != nil {
				continue
			}
			if err := c.writer.Flush(); err != nil {
				continue
			}
		case <-c.shutdownCtx.Done():
			// Flush remaining data on shutdown
			for {
				select {
				case data, ok := <-c.outputChan:
					if !ok {
						c.writer.Flush()
						return
					}
					if _, err := c.writer.Write(data); err != nil {
						continue
					}
				default:
					c.writer.Flush()
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
func (c *AsyncOutputCoordinator) HandleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		c.GracefulShutdown()
		os.Exit(0)
	}()
}
