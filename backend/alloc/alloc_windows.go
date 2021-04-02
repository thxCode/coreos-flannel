// Copyright 2021 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package alloc

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	log "k8s.io/klog"

	"github.com/flannel-io/flannel/backend"
	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/subnet"
)

func init() {
	backend.Register("alloc", New)
}

type AllocBackend struct {
	sm       subnet.Manager
	extIface *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	be := AllocBackend{
		sm:       sm,
		extIface: extIface,
	}
	return &be, nil
}

type netConf struct {
	// Name specifies the network name.
	Name string `json:"name,omitempty"`

	// NetworkType specifies the type of HNSNetwork, either "L2Bridge" or "L2Tunnel", default is "L2Bridge".
	NetworkType string `json:"networkType,omitempty"`

	// ApiVersion specifies the version of HCN Api, either 1 or 2, default is 1.
	ApiVersion int `json:"apiVersion,omitempty"`

	// DNSServerList specifies the DNS Servers, in form of a comma-separated list.
	DNSServerList string `json:"dnsServerList,omitempty"`

	// SyncInterval specifies the interval to sync.
	SyncInterval string `json:"syncInterval,omitempty"`
}

type netConfNetwork struct {
	netConf
	SubnetLease *subnet.Lease
	ExtIface    *backend.ExternalInterface
}

func (n *netConfNetwork) Lease() *subnet.Lease {
	return n.SubnetLease
}

func (n *netConfNetwork) MTU() int {
	return n.ExtIface.Iface.MTU
}

func (n *netConfNetwork) Run(ctx context.Context) {
	interval := 1 * time.Minute
	if n.SyncInterval != "" {
		if d, err := time.ParseDuration(n.SyncInterval); err == nil {
			interval = d
		}
	}

	// stop watching if sync interval is 0
	if interval == 0 {
		<-ctx.Done()
		return
	}

	expectedSubnet := n.Lease().Subnet
	expectedAddressPrefix := expectedSubnet.String()
	expectedGatewayAddress := (expectedSubnet.IP + 1).String()
	expectedPodGatewayAddress := expectedSubnet.IP + 2
	apiVersion := n.ApiVersion
	networkName := n.Name
	networkType := n.NetworkType
	bridgeEndpointName := getEndpointName(networkName)
	wait.NonSlidingUntilWithContext(ctx, func(ctx context.Context) {
		var exit bool

		if apiVersion == 2 {
			// Verify if the network exists and has the expected settings
			exit = true
			network, err := hcn.GetNetworkByName(networkName)
			if err != nil {
				log.Fatal("Failed to get HostComputeNetwork %s(%s): %v", networkName, networkType, err)
			}
			for _, ipam := range network.Ipams {
				for _, sn := range ipam.Subnets {
					if sn.IpAddressPrefix == expectedAddressPrefix {
						for _, route := range sn.Routes {
							if route.NextHop == expectedGatewayAddress && route.DestinationPrefix == "0.0.0.0/0" {
								exit = false
								log.V(4).Infof("Found existing HostComputeNetwork %s(%s)", networkName, networkType)
								break
							}
						}
						break
					}
				}
			}
			if exit {
				log.Fatal("Cannot get HostComputeNetwork %s(%s)", networkName, networkType)
			}
			// Verify if the bridge endpoint exists and has the expected settings
			exit = true
			bridgeEndpoint, err := hcn.GetEndpointByName(bridgeEndpointName)
			if err != nil {
				log.Fatal("Failed to get bridge HostComputeEndpoint %s: %v", bridgeEndpointName, err)
			}
			for _, route := range bridgeEndpoint.Routes {
				if route.NextHop == expectedGatewayAddress && route.DestinationPrefix == "0.0.0.0/0" {
					exit = false
					log.V(4).Infof("Found existing bridge HostComputeEndpoint %s", bridgeEndpointName)
					break
				}
			}
			if exit {
				log.Fatal("Cannot get bridge HostComputeEndpoint %s", bridgeEndpointName)
			}

			return
		}

		// Verify if the network exists and has the expected settings
		exit = true
		network, err := hcsshim.GetHNSNetworkByName(networkName)
		if err != nil {
			log.Fatal("Failed to get HNSNetwork %s(%s): %v", networkName, networkType, err)
		}
		for _, subnetObserved := range network.Subnets {
			if subnetObserved.AddressPrefix == expectedAddressPrefix && subnetObserved.GatewayAddress == expectedGatewayAddress {
				exit = false
				log.V(4).Infof("Found existing HNSNetwork %s(%s)", networkName, networkType)
				break
			}
		}
		if exit {
			log.Fatal("Cannot get HNSNetwork %s(%s)", networkName, networkType)
		}
		// Verify if the bridge endpoint exists and has the expected settings
		exit = true
		bridgeEndpoint, err := hcsshim.GetHNSEndpointByName(bridgeEndpointName)
		if err != nil {
			log.Fatal("Failed to get bridge HNSEndpoint %s: %v", bridgeEndpointName, err)
		}
		if bridgeEndpoint.IPAddress.String() == expectedPodGatewayAddress.String() {
			exit = false
			log.V(4).Infof("Found existing bridge HNSEndpoint %s", bridgeEndpointName)
		}
		if exit {
			log.Fatal("Cannot get bridge HNSEndpoint %s", bridgeEndpointName)
		}
	}, interval)
}

func (be *AllocBackend) RegisterNetwork(ctx context.Context, wg *sync.WaitGroup, config *subnet.Config) (backend.Network, error) {
	// Parse configuration
	var cfg netConf
	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, errors.Wrap(err, "error decoding windows alloc backend config")
		}
	}
	if len(cfg.Name) == 0 {
		cfg.Name = "cbr0"
	}
	if cfg.ApiVersion == 0 {
		cfg.ApiVersion = 1
	}
	if cfg.NetworkType == "" {
		cfg.NetworkType = "L2Bridge"
	}
	log.Infof("Alloc config: %+v", cfg)

	n := &netConfNetwork{
		netConf:  cfg,
		ExtIface: be.extIface,
	}

	// Acquire the lease form subnet manager
	attrs := subnet.LeaseAttrs{
		PublicIP: ip.FromIP(be.extIface.ExtAddr),
	}

	l, err := be.sm.AcquireLease(ctx, &attrs)
	switch err {
	case nil:
		n.SubnetLease = l
	case context.Canceled, context.DeadlineExceeded:
		return nil, err
	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	// Setup network according to HCN API version
	if cfg.ApiVersion == 2 {
		if err := hcn.V2ApiSupported(); err != nil {
			log.Warningf("Fallback to HCN V1 Api as the host is not supported")
			cfg.ApiVersion = 1
		}
	}
	if cfg.ApiVersion == 2 {
		err = setupHostComputeNetwork(n, cfg)
	} else {
		err = setupHNSNetwork(n, cfg)
	}
	if err != nil {
		return nil, err
	}
	return n, nil
}

func setupHostComputeNetwork(n backend.Network, cfg netConf) error {
	expectedSubnet := n.Lease().Subnet
	expectedAddressPrefix := expectedSubnet.String()
	expectedGatewayAddress := (expectedSubnet.IP + 1).String()
	expectedPodGatewayAddress := expectedSubnet.IP + 2
	networkName := cfg.Name
	networkType := cfg.NetworkType
	bridgeEndpointName := getEndpointName(networkName)
	var lastErr error

	// Ensure the given name network
	networks, err := hcn.ListNetworks()
	if err != nil {
		return errors.Wrapf(err, "failed to list HostComputeNetwork")
	}
	var networkObserved *hcn.HostComputeNetwork
	createNewNetwork := true
filterNetworks:
	for _, network := range networks {
		for _, ipam := range network.Ipams {
			for _, sn := range ipam.Subnets {
				isNameEqual := network.Name == networkName
				isConfigEqual := func() bool {
					if sn.IpAddressPrefix == expectedAddressPrefix {
						for _, route := range sn.Routes {
							if route.NextHop == expectedGatewayAddress && route.DestinationPrefix == "0.0.0.0/0" {
								return true
							}
						}
					}
					return false
				}()
				if isNameEqual || isConfigEqual {
					isTypeEqual := string(network.Type) == networkType
					if isNameEqual && isConfigEqual && isTypeEqual {
						createNewNetwork = false
						log.Infof("Found existing HostComputeNetwork %s(%s)", networkName, networkType)
					}
					networkObserved = &network
					break filterNetworks
				}
			}
		}
	}

	// Create the given name network or recreate if corrupted
	network := networkObserved
	if createNewNetwork {
		// Cleanup the corrupted network
		if networkObserved != nil {
			// Cleanup policies
			endpoints, err := hcn.ListEndpointsOfNetwork(networkObserved.Id)
			if err == nil {
				var epRefSet = sets.NewString()
				for _, ep := range endpoints {
					epRefSet.Insert(ep.Id)                  // raw
					epRefSet.Insert(strings.ToLower(ep.Id)) // lowercase
					epRefSet.Insert(strings.ToUpper(ep.Id)) // uppercase
				}
				if epRefSet.Len() > 0 {
					policies, err := hcn.ListLoadBalancers()
					if err == nil {
						for _, p := range policies {
							if epRefSet.HasAny(p.HostComputeEndpoints...) {
								_ = p.Delete()
							}
						}
					}
					log.Infof("Deleted policies of corrupted HostComputeNetwork %s(%s)", networkObserved.Name, networkObserved.Type)
				}
			}
			// Cleanup network
			if err := networkObserved.Delete(); err != nil {
				return errors.Wrapf(err, "failed to delete corrupted HostComputeNetwork %s(%s)", networkObserved.Name, networkObserved.Type)
			}
			log.Infof("Deleted corrupted HostComputeNetwork %s(%s)", networkObserved.Name, networkObserved.Type)
			networkObserved = nil
		}

		log.Infof("Attempting to create HostComputeNetwork %s(%s)", networkName, networkType)
		network = &hcn.HostComputeNetwork{
			Name: networkName,
			Type: hcn.L2Bridge,
			Ipams: []hcn.Ipam{
				{
					Subnets: []hcn.Subnet{
						{
							IpAddressPrefix: expectedAddressPrefix,
							Routes: []hcn.Route{
								{
									NextHop:           expectedGatewayAddress,
									DestinationPrefix: "0.0.0.0/0",
								},
							},
						},
					},
				},
			},
			SchemaVersion: hcn.SchemaVersion{
				Major: 2,
				Minor: 0,
			},
		}
		newNetwork, err := network.Create()
		if err != nil {
			return errors.Wrapf(err, "failed to create HostComputeNetwork %s(%s), %+v", networkName, networkType, network)
		}

		// Wait for the network to populate management IP
		log.Infof("Waiting to get management IP from HostComputeNetwork %s(%s)", networkName, networkType)
		var newNetworkID = newNetwork.Id
		err = wait.Poll(500*time.Millisecond, 30*time.Second, func() (done bool, err error) {
			newNetwork, lastErr = hcn.GetNetworkByID(newNetworkID)
			return hcnGetManagementIP(newNetwork) != "", nil
		})
		if err == wait.ErrWaitTimeout {
			if lastErr != nil {
				err = lastErr
			}
			return errors.Wrapf(err, "timeout, failed to get management IP from HostComputeNetwork %s(%s)", networkName, networkType)
		}

		// Wait for the interface with the management IP
		managmentIPString := hcnGetManagementIP(newNetwork)
		log.Infof("Waiting to verify net interface %q for HostComputeNetwork %s(%s)", managmentIPString, networkName, networkType)
		managementIP, err := ip.ParseIP4(managmentIPString)
		if err != nil {
			return errors.Wrapf(err, "failed to parse management IP %s", managmentIPString)
		}
		err = wait.Poll(500*time.Millisecond, 5*time.Second, func() (done bool, err error) {
			_, lastErr = ip.GetInterfaceByIP(managementIP.ToIP())
			return lastErr == nil, nil
		})
		if err == wait.ErrWaitTimeout {
			return errors.Wrapf(lastErr, "timeout, failed to verify net interface %s for HostComputeNetwork %s(%s)", managmentIPString, networkName, networkType)
		}

		log.Infof("Created HostComputeNetwork %s(%s)", networkName, networkType)
		network = newNetwork
	}
	if network == nil {
		return errors.Errorf("failed to create/get the given name HostComputeNetwork %s(%s)", networkName, networkType)
	}

	// Ensure the bridge endpoint of the given name network
	var bridgeEndpointObserved *hcn.HostComputeEndpoint
	createNewBridgeEndpoint := true
	endpoints, err := hcn.ListEndpointsOfNetwork(network.Id)
	if err != nil {
		return errors.Wrapf(err, "failed to list HostComputeEndpoint")
	}
	for _, endpoint := range endpoints {
		isNameEqual := endpoint.Name == bridgeEndpointName
		isConfigEqual := func() bool {
			for _, route := range endpoint.Routes {
				if route.NextHop == expectedGatewayAddress && route.DestinationPrefix == "0.0.0.0/0" {
					return true
				}
			}
			return false
		}()
		if isNameEqual || isConfigEqual {
			if isNameEqual && isConfigEqual {
				createNewBridgeEndpoint = false
				log.Infof("Found existing bridge HostComputeEndpoint %s", bridgeEndpointName)
			}
			bridgeEndpointObserved = &endpoint
			break
		}
	}

	// Create a bridge endpoint or recreate if corrupted
	bridgeEndpoint := bridgeEndpointObserved
	if createNewBridgeEndpoint {
		if bridgeEndpointObserved != nil {
			if err := bridgeEndpointObserved.Delete(); err != nil {
				return errors.Wrapf(err, "failed to delete existing bridge HostComputeEndpoint %s", bridgeEndpointName)
			}
			log.Infof("Deleted stale bridge HostComputeEndpoint %s", bridgeEndpointName)
		}

		log.Infof("Attempting to create bridge HostComputeEndpoint %s", bridgeEndpointName)
		bridgeEndpoint = &hcn.HostComputeEndpoint{
			Name:               bridgeEndpointName,
			HostComputeNetwork: network.Id,
			IpConfigurations: []hcn.IpConfig{
				{
					IpAddress:    expectedPodGatewayAddress.String(),
					PrefixLength: uint8(expectedSubnet.PrefixLen),
				},
			},
			Flags: hcn.EndpointFlagsNone,
			SchemaVersion: hcn.SchemaVersion{
				Major: 2,
				Minor: 0,
			},
		}
		if bridgeEndpoint, err = bridgeEndpoint.Create(); err != nil {
			return errors.Wrapf(err, "failed to create bridge HostComputeEndpoint %s, %+v", bridgeEndpointName, bridgeEndpoint)
		}

		log.Infof("Created bridge HostComputeEndpoint %s", bridgeEndpointName)
	}

	// Get host default namespace
	namespaces, err := hcn.ListNamespacesQuery(hcn.HostComputeQuery{
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Flags:  hcn.HostComputeQueryFlagsDetailed,
		Filter: `{"IsDefault":true}`,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to list host default HostComputeNamespace")
	}
	var namespace *hcn.HostComputeNamespace
	if len(namespaces) == 0 {
		namespace = hcn.NewNamespace(hcn.NamespaceTypeHostDefault)
		namespace, err = namespace.Create()
		if err != nil {
			return errors.Wrapf(err, "failed to create host default HostComputerNamespace")
		}
	} else {
		namespace = &namespaces[0]
	}

	// Wait for the bridge endpoint to attach to the host
	log.Infof("Waiting to attach bridge HostComputeEndpoint %s to host", bridgeEndpointName)
	err = wait.Poll(500*time.Millisecond, 5*time.Second, func() (done bool, err error) {
		lastErr = bridgeEndpoint.NamespaceAttach(namespace.Id)
		if lastErr == nil {
			return true, nil
		}
		// See https://github.com/coreos/flannel/issues/1391 and
		// hcsshim lacks some validations to detect the error, so we judge it by error message.
		if strings.Contains(lastErr.Error(), "This requested operation is invalid as endpoint is already part of a network namespace.") {
			return true, nil
		}
		return false, nil
	})
	if err == wait.ErrWaitTimeout {
		return errors.Wrapf(lastErr, "failed to hot attach bridge HostComputeEndpoint %s to host default HostComputeNamespace", bridgeEndpointName)
	}
	log.Infof("Attached bridge HostComputeEndpoint %s to host default HostComputeNamespace successfully", bridgeEndpointName)

	// Enable forwarding on the host interface and bridge endpoint
	for _, interfaceIpAddress := range []string{hcnGetManagementIP(network), bridgeEndpoint.IpConfigurations[0].IpAddress} {
		ipv4, err := ip.ParseIP4(interfaceIpAddress)
		if err != nil {
			return errors.Wrapf(err, "failed to parse IP %s", interfaceIpAddress)
		}

		netInterface, err := ip.GetInterfaceByIP(ipv4.ToIP())
		if err != nil {
			return errors.Wrapf(err, "failed to find interface for IP %s", interfaceIpAddress)
		}

		if err := ip.EnableForwardingForInterface(netInterface); err != nil {
			return errors.Wrapf(err, "failed to enable forwarding on %s(%s) index %d", netInterface.Name, interfaceIpAddress, netInterface.Index)
		}
		log.Infof("Enabled forwarding on %s(%s) index %d", netInterface.Name, interfaceIpAddress, netInterface.Index)

		if err = ip.SetMTUForInterface(netInterface, 1500); err != nil {
			return errors.Wrapf(err, "failed to configure MTU to 1500 on %s(%s) index %d", netInterface.Name, interfaceIpAddress, netInterface.Index)
		}
		log.Infof("Configured MTU to 1500 on %s(%s) index %d", netInterface.Name, interfaceIpAddress, netInterface.Index)
	}

	return nil
}

func setupHNSNetwork(n backend.Network, cfg netConf) error {
	expectedSubnet := n.Lease().Subnet
	expectedAddressPrefix := expectedSubnet.String()
	expectedGatewayAddress := (expectedSubnet.IP + 1).String()
	expectedPodGatewayAddress := expectedSubnet.IP + 2
	networkName := cfg.Name
	networkType := cfg.NetworkType
	bridgeEndpointName := getEndpointName(networkName)
	var lastErr error

	// Ensure the given name network
	networks, err := hcsshim.HNSListNetworkRequest("GET", "", "")
	if err != nil {
		return errors.Wrapf(err, "failed to list HNSNetwork")
	}
	var networkObserved *hcsshim.HNSNetwork
	createNewNetwork := true
filterNetworks:
	for _, network := range networks {
		for _, sn := range network.Subnets {
			isNameEqual := network.Name == networkName
			isConfigEqual := sn.AddressPrefix == expectedAddressPrefix && sn.GatewayAddress == expectedGatewayAddress
			if isNameEqual || isConfigEqual {
				isTypeEqual := network.Type == networkType
				if isNameEqual && isConfigEqual && isTypeEqual {
					createNewNetwork = false
					log.Infof("Found existing HNSNetwork %s(%s)", networkName, networkType)
				}
				networkObserved = &network
				break filterNetworks
			}
		}
	}

	// Create the given name network or recreate if corrupted
	network := networkObserved
	if createNewNetwork {
		// Cleanup the corrupted network
		if networkObserved != nil {
			// Cleanup policies
			endpoints, err := hcsshim.HNSListEndpointRequest()
			if err == nil {
				var epRefSet = sets.NewString()
				for _, ep := range endpoints {
					if ep.VirtualNetwork == networkObserved.Id {
						epRefSet.Insert("/endpoints/" + ep.Id)                  // raw
						epRefSet.Insert("/endpoints/" + strings.ToLower(ep.Id)) // lowercase
						epRefSet.Insert("/endpoints/" + strings.ToUpper(ep.Id)) // uppercase
					}
				}
				if epRefSet.Len() > 0 {
					policies, err := hcsshim.HNSListPolicyListRequest()
					if err == nil {
						for _, p := range policies {
							if epRefSet.HasAny(p.EndpointReferences...) {
								_, _ = p.Delete()
							}
						}
						log.Infof("Deleted policies of corrupted HNSNetwork %s(%s)", networkObserved.Name, networkObserved.Type)
					}
				}
			}
			// Cleanup network
			if _, err := networkObserved.Delete(); err != nil {
				return errors.Wrapf(err, "failed to delete corrupted HNSNetwork %s(%s)", networkObserved.Name, networkObserved.Type)
			}
			log.Infof("Deleted corrupted HNSNetwork %s(%s)", networkObserved.Name, networkObserved.Type)
			networkObserved = nil
		}

		log.Infof("Attempting to create HNSNetwork %s(%s)", networkName, networkType)
		network = &hcsshim.HNSNetwork{
			Name:          networkName,
			Type:          networkType,
			DNSServerList: cfg.DNSServerList,
			Subnets: []hcsshim.Subnet{
				{
					AddressPrefix:  expectedAddressPrefix,
					GatewayAddress: expectedGatewayAddress,
				},
			},
		}
		newNetwork, err := network.Create()
		if err != nil {
			return errors.Wrapf(err, "failed to create HNSNetwork %s(%s), %+v", networkName, networkType, network)
		}

		// Wait for the network to populate management IP
		log.Infof("Waiting to get management IP from HNSNetwork %s(%s)", networkName, networkType)
		var newNetworkID = newNetwork.Id
		err = wait.Poll(500*time.Millisecond, 30*time.Second, func() (done bool, err error) {
			newNetwork, lastErr = hcsshim.GetHNSNetworkByID(newNetworkID)
			return newNetwork != nil && len(newNetwork.ManagementIP) != 0, nil
		})
		if err == wait.ErrWaitTimeout {
			if lastErr != nil {
				err = lastErr
			}
			return errors.Wrapf(err, "timeout, failed to get management IP from HNSNetwork %s(%s)", networkName, networkType)
		}

		// Wait for the interface with the management IP
		managmentIPString := newNetwork.ManagementIP
		log.Infof("Waiting to verify net interface %q for HNSNetwork %s(%s)", managmentIPString, networkName, networkType)
		managementIP, err := ip.ParseIP4(managmentIPString)
		if err != nil {
			return errors.Wrapf(err, "failed to parse management IP %s", managmentIPString)
		}
		err = wait.Poll(500*time.Millisecond, 5*time.Second, func() (done bool, err error) {
			_, lastErr = ip.GetInterfaceByIP(managementIP.ToIP())
			return lastErr == nil, nil
		})
		if err == wait.ErrWaitTimeout {
			return errors.Wrapf(lastErr, "timeout, failed to verify net interface %s for HNSNetwork %s(%s)", managmentIPString, networkName, networkType)
		}

		log.Infof("Created HNSNetwork %s(%s)", networkName, networkType)
		network = newNetwork
	}
	if network == nil {
		return errors.Errorf("failed to create/get the given name HNSNetwork %s(%s)", networkName, networkType)
	}

	// Ensure the bridge endpoint of the given name network
	var bridgeEndpointObserved *hcsshim.HNSEndpoint
	createNewBridgeEndpoint := true
	endpoints, err := hcsshim.HNSListEndpointRequest()
	if err != nil {
		return errors.Wrapf(err, "failed to list HNSEndpoints")
	}
	for _, endpoint := range endpoints {
		if endpoint.VirtualNetwork == network.Id {
			isNameEqual := endpoint.Name == bridgeEndpointName
			isConfigEqual := endpoint.IPAddress.String() == expectedPodGatewayAddress.String()
			if isNameEqual || isConfigEqual {
				if isNameEqual && isConfigEqual {
					createNewBridgeEndpoint = false
					log.Infof("Found existing bridge HNSEndpoint %s", bridgeEndpointName)
				}
				bridgeEndpointObserved = &endpoint
				break
			}
		}
	}

	// Create the bridge endpoint or recreate if corrupted
	bridgeEndpoint := bridgeEndpointObserved
	if createNewBridgeEndpoint {
		if bridgeEndpointObserved != nil {
			if _, err = bridgeEndpointObserved.Delete(); err != nil {
				return errors.Wrapf(err, "failed to delete existing bridge HNSEndpoint %s", bridgeEndpointName)
			}
			log.Infof("Deleted stale bridge HNSEndpoint %s", bridgeEndpointName)
		}

		log.Infof("Attempting to create bridge HNSEndpoint %s", bridgeEndpointName)
		bridgeEndpoint = &hcsshim.HNSEndpoint{
			Name:           bridgeEndpointName,
			IPAddress:      expectedPodGatewayAddress.ToIP(),
			VirtualNetwork: network.Id,
		}
		if bridgeEndpoint, err = bridgeEndpoint.Create(); err != nil {
			return errors.Wrapf(err, "failed to create bridge HNSEndpoint %s, %+v", bridgeEndpointName, bridgeEndpoint)
		}

		log.Infof("Created bridge HNSEndpoint %s", bridgeEndpointName)
	}

	// Wait for the bridge endpoint to attach to the host
	log.Infof("Waiting to attach bridge HNSEndpoint %s to host", bridgeEndpointName)
	err = wait.Poll(500*time.Millisecond, 5*time.Second, func() (done bool, err error) {
		lastErr = bridgeEndpoint.HostAttach(1)
		if lastErr == nil {
			return true, nil
		}
		// See https://github.com/coreos/flannel/issues/1391 and
		// hcsshim lacks some validations to detect the error, so we judge it by error message.
		if strings.Contains(lastErr.Error(), "This endpoint is already attached to the switch.") {
			return true, nil
		}
		return false, nil
	})
	if err == wait.ErrWaitTimeout {
		return errors.Wrapf(lastErr, "failed to hot attach bridge HNSEndpoint %s to host compartment", bridgeEndpointName)
	}
	log.Infof("Attached bridge HNSEndpoint %s to host successfully", bridgeEndpointName)

	// Enable forwarding on the host interface and bridge endpoint
	for _, interfaceIpAddress := range []string{network.ManagementIP, bridgeEndpoint.IPAddress.String()} {
		ipv4, err := ip.ParseIP4(interfaceIpAddress)
		if err != nil {
			return errors.Wrapf(err, "failed to parse IP %s", interfaceIpAddress)
		}
		netInterface, err := ip.GetInterfaceByIP(ipv4.ToIP())
		if err != nil {
			return errors.Wrapf(err, "failed to find net interface for IP %s", interfaceIpAddress)
		}

		if err := ip.EnableForwardingForInterface(netInterface); err != nil {
			return errors.Wrapf(err, "failed to enable forwarding on %s(%s) index %d", netInterface.Name, interfaceIpAddress, netInterface.Index)
		}
		log.Infof("Enabled forwarding on %s(%s) index %d", netInterface.Name, interfaceIpAddress, netInterface.Index)

		if err = ip.SetMTUForInterface(netInterface, 1500); err != nil {
			return errors.Wrapf(err, "failed to configure MTU to 1500 on %s(%s) index %d", netInterface.Name, interfaceIpAddress, netInterface.Index)
		}
		log.Infof("Configured MTU to 1500 on %s(%s) index %d", netInterface.Name, interfaceIpAddress, netInterface.Index)
	}

	return nil
}

func hcnGetManagementIP(network *hcn.HostComputeNetwork) string {
	if network == nil {
		return ""
	}

	for _, policy := range network.Policies {
		if policy.Type == hcn.ProviderAddress {
			policySettings := hcn.ProviderAddressEndpointPolicySetting{}
			err := json.Unmarshal(policy.Settings, &policySettings)
			if err != nil {
				return ""
			}
			return policySettings.ProviderAddress
		}
	}
	return ""
}

func getEndpointName(networkName string) string {
	return networkName + "_ep"
}
