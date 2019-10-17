// Copyright 2018 flannel authors
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

package vxlan

import (
	"encoding/json"
	"time"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/coreos/flannel/pkg/ip"
	log "github.com/golang/glog"
	"github.com/juju/errors"
	"github.com/rakelkar/gonetsh/netsh"
	"k8s.io/apimachinery/pkg/util/wait"
	utilexec "k8s.io/utils/exec"
)

type vxlanDeviceAttrs struct {
	vni           uint32
	name          string
	addressPrefix ip.IP4Net
}

type vxlanDevice struct {
	link          *vxlan
	directRouting bool
}

func newVXLANDevice(devAttrs *vxlanDeviceAttrs) (*vxlanDevice, error) {
	link := &vxlan{
		VNI:     devAttrs.vni,
		Name:    devAttrs.name,
		SrcAddr: devAttrs.addressPrefix,
	}

	link, err := ensureLink(link)
	if err != nil {
		return nil, err
	}

	return &vxlanDevice{
		link: link,
	}, nil
}

type vxlan struct {
	VNI     uint32
	Name    string
	SrcAddr ip.IP4Net

	Network *hcn.HostComputeNetwork
	Id      string
}

func ensureLink(v *vxlan) (*vxlan, error) {
	expectedNetwork, err := initHCN(v)
	if err != nil {
		return nil, errors.Annotatef(err, "failed to init HostComputeNetwork %s", v.Name)
	}

	createNetwork := true
	networkName := expectedNetwork.Name
	expectedAddressPrefix := v.SrcAddr.String()

	// 1. Check if the HostComputeNetwork exists and has the expected settings
	existingNetwork, err := hcn.GetNetworkByName(networkName)
	if err == nil {
		if existingNetwork.Type == expectedNetwork.Type {
			if existingNetwork.Ipams[0].Subnets[0].IpAddressPrefix == expectedAddressPrefix {
				createNetwork = false
				log.Infof("Found existing HostComputeNetwork %s", networkName)
			}
		}
	}

	// 2. Create a new HNSNetwork
	if createNetwork {
		if existingNetwork != nil {
			if err := existingNetwork.Delete(); err != nil {
				return nil, errors.Annotatef(err, "failed to delete existing HostComputeNetwork %s", networkName)
			}
			log.Infof("Deleted stale HostComputeNetwork %s", networkName)
		}

		log.Infof("Attempting to create HostComputeNetwork %v", expectedNetwork)
		newNetwork, err := expectedNetwork.Create()
		if err != nil {
			return nil, errors.Annotatef(err, "failed to create HostComputeNetwork %s", networkName)
		}

		var waitErr, lastErr error
		// Wait for the network to populate Management IP
		log.Infof("Waiting to get ManagementIP from HostComputeNetwork %s", networkName)
		waitErr = wait.Poll(500*time.Millisecond, 5*time.Second, func() (done bool, err error) {
			newNetwork, lastErr = hcn.GetNetworkByID(newNetwork.Id)
			return newNetwork != nil && len(getManagementIP(newNetwork)) != 0, nil
		})
		if waitErr == wait.ErrWaitTimeout {
			return nil, errors.Annotatef(lastErr, "timeout, failed to get management IP from HostComputeNetwork %s", networkName)
		}

		managementIP := getManagementIP(newNetwork)
		// Wait for the interface with the management IP
		netshHelper := netsh.New(utilexec.New())
		log.Infof("Waiting to get net interface for HostComputeNetwork %s (%s)", networkName, managementIP)
		waitErr = wait.Poll(500*time.Millisecond, 5*time.Second, func() (done bool, err error) {
			_, lastErr = netshHelper.GetInterfaceByIP(managementIP)
			return lastErr == nil, nil
		})
		if waitErr == wait.ErrWaitTimeout {
			return nil, errors.Annotatef(lastErr, "timeout, failed to get net interface for HostComputeNetwork %s (%s)", networkName, managementIP)
		}

		log.Infof("Created HostComputeNetwork %s", networkName)
		existingNetwork = newNetwork
	}

	if existingNetwork == nil {
		return nil, errors.Errorf("could not get HostComputeNetwork %s", networkName)
	}

	addHostRoute := true
	for _, policy := range existingNetwork.Policies {
		if policy.Type == hcn.HostRoute {
			addHostRoute = false
		}
	}
	if addHostRoute {
		hostRoutePolicy := hcn.NetworkPolicy{
			Type:     hcn.HostRoute,
			Settings: []byte("{}"),
		}

		networkRequest := hcn.PolicyNetworkRequest{
			Policies: []hcn.NetworkPolicy{hostRoutePolicy},
		}
		err = existingNetwork.AddPolicy(networkRequest)
		if err != nil {
			log.Infof("Could not apply HostRoute policy for local host to local pod connectivity. This policy requires Windows 18321.1000.19h1_release.190117-1502 or newer")
		}
	}

	v.Network = existingNetwork
	v.Id = existingNetwork.Id
	return v, nil
}

func getManagementIP(network *hcn.HostComputeNetwork) string {
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

func createSubnet(AddressPrefix string, NextHop string, DestPrefix string) *hcn.Subnet {
	return &hcn.Subnet{
		IpAddressPrefix: AddressPrefix,
		Routes: []hcn.Route{
			{
				NextHop:           NextHop,
				DestinationPrefix: DestPrefix,
			},
		},
	}
}

func initHCN(v *vxlan) (*hcn.HostComputeNetwork, error) {
	subnet := createSubnet(v.SrcAddr.String(), (v.SrcAddr.IP + 1).String(), "0.0.0.0/0")
	network := &hcn.HostComputeNetwork{
		Type: "Overlay",
		Name: v.Name,
		Ipams: []hcn.Ipam{
			{
				Type: "Static",
				Subnets: []hcn.Subnet{
					*subnet,
				},
			},
		},
		Flags: hcn.EnableNonPersistent,
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
	}

	vsid := &hcn.VsidPolicySetting{
		IsolationId: v.VNI,
	}
	vsidJson, err := json.Marshal(vsid)
	if err != nil {
		return nil, err
	}

	sp := &hcn.SubnetPolicy{
		Type: hcn.VSID,
	}
	sp.Settings = vsidJson

	spJson, err := json.Marshal(sp)
	if err != nil {
		return nil, err
	}

	network.Ipams[0].Subnets[0].Policies = append(network.Ipams[0].Subnets[0].Policies, spJson)

	return network, nil
}
