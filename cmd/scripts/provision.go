package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/hetznercloud/hcloud-go/v2/hcloud/exp/actionutil"
)

func main() {
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
		log.Fatalf("error creating server: %s\n", err)
	}

	err = client.Action.WaitFor(ctx, actionutil.AppendNext(result.Action, result.NextActions)...)
	if err != nil {
		log.Fatalf("error creating server: %s\n", err)
	}

	server, _, err := client.Server.GetByID(ctx, result.Server.ID)
	if err != nil {
		log.Fatalf("error retrieving server: %s\n", err)
	}
	if server != nil {
		fmt.Printf("server is called %q\n", server.Name)
	} else {
		fmt.Println("server not found")
	}
}
