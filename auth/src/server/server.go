package server

import (
	"context"
	"github.com/gin-gonic/gin"
	"net/http"
)

// Server is the public interface for server operations
type Server interface {
	Start() error
	Shutdown(ctx context.Context) error
	Engine() *gin.Engine
}

// ginServer is the private implementation of Server
type ginServer struct {
	addr    string
	engine  *gin.Engine
	httpSrv *http.Server
}

func (s *ginServer) Start() error {
	return s.httpSrv.ListenAndServe()
}

func (s *ginServer) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

func (s *ginServer) Engine() *gin.Engine {
	return s.engine
}

// NewServer creates a new Server instance
func NewServer(addr string) Server {
	engine := gin.Default()
	httpSrv := &http.Server{
		Addr:    addr,
		Handler: engine,
	}
	return &ginServer{
		addr:    addr,
		engine:  engine,
		httpSrv: httpSrv,
	}
}
