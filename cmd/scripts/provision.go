package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/hetznercloud/hcloud-go/v2/hcloud/exp/actionutil"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx := context.Background()

	// Token from environment variable
	token := os.Getenv("HCLOUD_TOKEN")
	if token == "" {
		panic("HCLOUD_TOKEN environment variable is not set")
	}

	client := hcloud.NewClient(hcloud.WithToken(token))

	result, _, err := client.Server.Create(ctx, hcloud.ServerCreateOpts{
		Name:       "Twititu",
		Image:      &hcloud.Image{Name: "ubuntu-24.0"},
		ServerType: &hcloud.ServerType{Name: "cpx22"},
		Location:   &hcloud.Location{Name: "hel1"},
	})
	if err != nil {
		logger.Error("error creating server", slog.String("error", err.Error()))
	}

	err = client.Action.WaitFor(ctx, actionutil.AppendNext(result.Action, result.NextActions)...)
	if err != nil {
		logger.Error("error creating server", slog.String("error", err.Error()))
	}

	server, _, err := client.Server.GetByID(ctx, result.Server.ID)
	if err != nil {
		logger.Error("error retrieving server", slog.String("error", err.Error()))
	}
	if server != nil {
		logger.Info("server is called", slog.String("name", server.Name))
	} else {
		logger.Info("server not found")
	}
}
