package main

import (
	"fmt"

	"github.com/kelar1s/sso/internal/config"
)

func main() {
	cfg := config.MustLoad()

	fmt.Println(cfg)

	// TODO: init logger (slog)

	// TODO: init app

	// TODO: start gRPC server
}
