package main

import (
	"context"
	"log"
	"log/slog"
	"net"
	"os"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/hetznercloud/hcloud-go/v2/hcloud/exp/actionutil"
	"github.com/joho/godotenv"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx := context.Background()

	// Load the .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Token from environment variable
	token := os.Getenv("HCLOUD_TOKEN")
	if token == "" {
		panic("HCLOUD_TOKEN environment variable is not set")
	}

	client := hcloud.NewClient(hcloud.WithToken(token))

	sshKey, err := getSSHKeyByName(ctx, client, "default")
	if err != nil {
		logger.Error("error retrieving SSH key", slog.String("error", err.Error()))
		return
	}
	if sshKey == nil {
		logger.Error("SSH key not found", slog.String("key_name", "default"))
		return
	}

	// Create firewall
	firewall, err := createFirewall(ctx, client, "Twititu Firewall")
	if err != nil {
		logger.Error("error creating firewall", slog.String("error", err.Error()))
		return
	}

	result, _, err := client.Server.Create(ctx, hcloud.ServerCreateOpts{
		Name:       "Twititu",
		Image:      &hcloud.Image{Name: "ubuntu-24.04"},
		ServerType: &hcloud.ServerType{Name: "cx23"},
		Location:   &hcloud.Location{Name: "fsn1"},
		SSHKeys:    []*hcloud.SSHKey{sshKey},
		Firewalls:  []*hcloud.ServerCreateFirewall{{Firewall: *firewall}},
	})
	if err != nil {
		logger.Error("error creating server", slog.String("error", err.Error()))
		return
	}

	err = client.Action.WaitFor(ctx, actionutil.AppendNext(result.Action, result.NextActions)...)
	if err != nil {
		logger.Error("error creating server", slog.String("error", err.Error()))
		return
	}

	server, _, err := client.Server.GetByID(ctx, result.Server.ID)
	if err != nil {
		logger.Error("error retrieving server", slog.String("error", err.Error()))
		return
	}
	if server != nil {
		logger.Info("server created", slog.String("server_id", server.PublicNet.IPv4.IP.String()))
		return
	} else {
		logger.Info("server not found")
		return
	}
}

func getSSHKeyByName(ctx context.Context, client *hcloud.Client, name string) (*hcloud.SSHKey, error) {
	sshKeys, _, err := client.SSHKey.List(ctx, hcloud.SSHKeyListOpts{Name: name})
	if err != nil {
		return nil, err
	}
	if len(sshKeys) == 0 {
		return nil, nil
	}
	return sshKeys[0], nil
}

func createFirewall(ctx context.Context, client *hcloud.Client, name string) (*hcloud.Firewall, error) {
	httpDescription := "Allow HTTP"
	httpPort := "80"
	httpsDescription := "Allow HTTPS"
	httpsPort := "443"
	grafanaDescription := "Allow Grafana"
	grafanaPort := "3001"
	kibanaDescription := "Allow Kibana"
	kibanaPort := "5601"
	sshDescription := "Allow SSH"
	sshPort := "22"

	allIPs := []net.IPNet{
		{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)},
		{IP: net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: net.CIDRMask(0, 128)},
	}

	firewall, _, err := client.Firewall.Create(ctx, hcloud.FirewallCreateOpts{
		Name: name,
		Rules: []hcloud.FirewallRule{
			{
				Description: &httpDescription,
				Direction:   hcloud.FirewallRuleDirectionIn,
				Protocol:    hcloud.FirewallRuleProtocolTCP,
				Port:        &httpPort,
				SourceIPs:   allIPs,
			},
			{
				Description: &httpsDescription,
				Direction:   hcloud.FirewallRuleDirectionIn,
				Protocol:    hcloud.FirewallRuleProtocolTCP,
				Port:        &httpsPort,
				SourceIPs:   allIPs,
			},
			{
				Description: &grafanaDescription,
				Direction:   hcloud.FirewallRuleDirectionIn,
				Protocol:    hcloud.FirewallRuleProtocolTCP,
				Port:        &grafanaPort,
				SourceIPs:   allIPs,
			},
			{
				Description: &kibanaDescription,
				Direction:   hcloud.FirewallRuleDirectionIn,
				Protocol:    hcloud.FirewallRuleProtocolTCP,
				Port:        &kibanaPort,
				SourceIPs:   allIPs,
			},
			{
				Description: &sshDescription,
				Direction:   hcloud.FirewallRuleDirectionIn,
				Protocol:    hcloud.FirewallRuleProtocolTCP,
				Port:        &sshPort,
				SourceIPs:   allIPs,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return firewall.Firewall, nil
}
