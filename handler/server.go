package handler

import (
	"github.com/chandra-phang/user-registration/handler/middleware"
	"github.com/chandra-phang/user-registration/repository"
)

type Server struct {
	Repository repository.RepositoryInterface
	JwtService middleware.IJwtService
}

type NewServerOptions struct {
	Repository repository.RepositoryInterface
	JwtService middleware.IJwtService
}

func NewServer(opts NewServerOptions) *Server {
	return &Server{opts.Repository, opts.JwtService}
}
