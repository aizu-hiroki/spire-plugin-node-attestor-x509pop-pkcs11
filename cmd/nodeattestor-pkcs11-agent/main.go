package main

import (
	"github.com/aizu-hiroki/spire-plugin-node-attestor-x509pop-pkcs11/pkg/pkcs11attestor/agent"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestoragentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

func main() {
	plugin := agent.New()
	pluginmain.Serve(
		nodeattestoragentv1.NodeAttestorPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
