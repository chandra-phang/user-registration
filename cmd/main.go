package main

import (
	"os"

	"github.com/chandra-phang/sawit-pro/generated"
	"github.com/chandra-phang/sawit-pro/handler"
	"github.com/chandra-phang/sawit-pro/handler/middleware"
	"github.com/chandra-phang/sawit-pro/repository"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	var server generated.ServerInterface = newServer()

	generated.RegisterHandlers(e, server)
	e.Logger.Fatal(e.Start(":1323"))
}

func newServer() *handler.Server {
	dbDsn := os.Getenv("DATABASE_URL")
	var repo repository.RepositoryInterface = repository.NewRepository(repository.NewRepositoryOptions{
		Dsn: dbDsn,
	})

	jwtService := middleware.InitAuthService(os.Getenv("PRIVATE_KEY_PATH"), os.Getenv("PUBLIC_KEY_PATH"))

	opts := handler.NewServerOptions{
		Repository: repo,
		JwtService: jwtService,
	}
	return handler.NewServer(opts)
}
