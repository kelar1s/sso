package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/kelar1s/sso/internal/app/grpc"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, storagePath string, tokenTTL time.Duration) *App {
	// TODO init storage

	// TODO init auth serv

	grpcApp := grpcapp.New(log, grpcPort)

	return &App{GRPCSrv: grpcApp}
}
