// Copyright 2015 flannel authors
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

// Some design notes:
// VXLAN encapsulates L2 packets (though flannel is L3 only so don't expect to be able to send L2 packets across hosts)
// Windows overlay decap works at L2 and so it needs the correct destination MAC for the remote host to work.
// Windows does not expose an L3Miss interface so for now all possible remote IP/MAC pairs have to be configured upfront.
//
// In this scheme the scaling of table entries (per host) is:
//  - 1 network entry for the overlay network
//  - 1 endpoint per local container
//  - N remote endpoints remote node (total endpoints =
import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	log "github.com/golang/glog"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/util/wait"
)

func init() {
	backend.Register("vxlan", New)
}

const (
	defaultVNI = 4096
	vxlanPort  = 4789
)

type VXLANBackend struct {
	subnetMgr subnet.Manager
	extIface  *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	backend := &VXLANBackend{
		subnetMgr: sm,
		extIface:  extIface,
	}

	return backend, nil
}

func newSubnetAttrs(publicIP net.IP, mac net.HardwareAddr) (*subnet.LeaseAttrs, error) {
	var hardwareAddress hardwareAddr
	if mac != nil {
		hardwareAddress = hardwareAddr(mac)
	}
	leaseAttrs := &vxlanLeaseAttrs{
		VtepMAC: hardwareAddress,
	}
	data, err := json.Marshal(&leaseAttrs)
	if err != nil {
		return nil, err
	}

	return &subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(publicIP),
		BackendType: "vxlan",
		BackendData: json.RawMessage(data),
	}, nil
}

func (be *VXLANBackend) RegisterNetwork(ctx context.Context, wg sync.WaitGroup, config *subnet.Config) (backend.Network, error) {
	// 1. Parse configuration
	cfg := struct {
		Name          string
		VNI           int
		Port          int
		GBP           bool
		DirectRouting bool
	}{
		VNI:  defaultVNI,
		Port: vxlanPort,
	}

	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding VXLAN backend config: %v", err)
		}
	}

	// 2. Verify configuration
	if cfg.VNI < defaultVNI {
		return nil, fmt.Errorf("invalid VXLAN backend config. VNI [%v] must be greater than or equal to %v on Windows", cfg.VNI, defaultVNI)
	}
	if cfg.Port != vxlanPort {
		return nil, fmt.Errorf("invalid VXLAN backend config. Port [%v] is not supported on Windows. Omit the setting to default to port %v", cfg.Port, vxlanPort)
	}
	if cfg.DirectRouting {
		return nil, errors.New("invalid VXLAN backend config. DirectRouting is not supported on Windows")
	}
	if cfg.GBP {
		return nil, errors.New("invalid VXLAN backend config. GBP is not supported on Windows")
	}
	if len(cfg.Name) == 0 {
		cfg.Name = fmt.Sprintf("flannel.%v", cfg.VNI)
	}
	log.Infof("VXLAN config: Name=%s VNI=%d Port=%d GBP=%v DirectRouting=%v", cfg.Name, cfg.VNI, cfg.Port, cfg.GBP, cfg.DirectRouting)

	err := hcn.RemoteSubnetSupported()
	if err != nil {
		return nil, err
	}

	// 3. Create device by a nil MAC
	// Windows VxLan need a lease to create the HNS network
	subnetAttrs, err := newSubnetAttrs(be.extIface.ExtAddr, nil)
	if err != nil {
		return nil, err
	}

	lease, err := be.subnetMgr.AcquireLease(ctx, subnetAttrs)
	switch err {
	case nil:
	case context.Canceled, context.DeadlineExceeded:
		return nil, err
	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	devAttrs := vxlanDeviceAttrs{
		vni:           uint32(cfg.VNI),
		name:          cfg.Name,
		addressPrefix: lease.Subnet,
	}
	dev, err := newVXLANDevice(&devAttrs)
	if err != nil {
		return nil, err
	}
	dev.directRouting = cfg.DirectRouting

	// 4. Get the real MAC from the created device
	var mac net.HardwareAddr
	waitErr := wait.Poll(1*time.Second, 30*time.Second, func() (done bool, err error) {
		hnsNetwork, err := hcn.GetNetworkByName(devAttrs.name)
		if err != nil {
			return false, nil
		}

		var macHash string
		for _, policy := range hnsNetwork.Policies {
			if policy.Type == hcn.DrMacAddress {
				policySettings := hcn.DrMacAddressNetworkPolicySetting{}
				err := json.Unmarshal(policy.Settings, &policySettings)
				if err != nil {
					return false, fmt.Errorf("failed to unmarshal DrMacAddress settings")
				}

				macHash = policySettings.Address
				break
			}
		}
		if len(macHash) == 0 {
			return false, fmt.Errorf("failed to get DrMacAddress from HNSNetwork %s ", devAttrs.name)
		}

		mac, err = net.ParseMAC(macHash)
		if err != nil {
			return false, fmt.Errorf("failed to parse DR MAC %v: %v", macHash, err)
		}

		return true, nil
	})
	if waitErr != nil {
		if waitErr == wait.ErrWaitTimeout {
			return nil, fmt.Errorf("timeout, failed to get HNSNetwork %s", devAttrs.name)
		}
		return nil, waitErr
	}

	// 5. Renew the lease with mac
	renewSubnetAttrs, err := newSubnetAttrs(be.extIface.ExtAddr, mac)
	if err != nil {
		return nil, fmt.Errorf("failed to create renew subnet lease attrs, %v", err)
	}
	lease.Attrs = *renewSubnetAttrs

	err = be.subnetMgr.RenewLease(ctx, lease)
	switch err {
	case nil:
	case context.Canceled, context.DeadlineExceeded:
		return nil, err
	default:
		return nil, fmt.Errorf("failed to renew lease: %v", err)
	}

	return newNetwork(be.subnetMgr, be.extIface, dev, ip.IP4Net{}, lease)
}

// So we can make it JSON (un)marshalable
type hardwareAddr net.HardwareAddr

func (hw hardwareAddr) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", net.HardwareAddr(hw))), nil
}

func (hw *hardwareAddr) UnmarshalJSON(bytes []byte) error {
	if len(bytes) < 2 || bytes[0] != '"' || bytes[len(bytes)-1] != '"' {
		return fmt.Errorf("error parsing hardware addr")
	}

	bytes = bytes[1 : len(bytes)-1]

	mac, err := net.ParseMAC(string(bytes))
	if err != nil {
		return err
	}

	*hw = hardwareAddr(mac)
	return nil
}
