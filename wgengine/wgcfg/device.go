// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"errors"
	"io"
	"sort"

	"tailscale.com/types/logger"
	"tailscale.com/wgengine/wgdevice"
)

// DeviceConfig reads the current configuration from a WireGuard device
// in UAPI format. Works with both wireguard-go and gotatun backends.
func DeviceConfig(d wgdevice.Device) (*Config, error) {
	r, w := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- d.IpcGetOperation(w)
		w.Close()
	}()
	cfg, fromErr := FromUAPI(r)
	r.Close()
	getErr := <-errc
	err := errors.Join(getErr, fromErr)
	if err != nil {
		return nil, err
	}
	sort.Slice(cfg.Peers, func(i, j int) bool {
		return cfg.Peers[i].PublicKey.Less(cfg.Peers[j].PublicKey)
	})
	return cfg, nil
}

// ReconfigDevice replaces the existing device configuration with cfg.
// Works with both wireguard-go and gotatun backends via the UAPI protocol.
func ReconfigDevice(d wgdevice.Device, cfg *Config, logf logger.Logf) (err error) {
	defer func() {
		if err != nil {
			logf("wgcfg.Reconfig failed: %v", err)
		}
	}()

	prev, err := DeviceConfig(d)
	if err != nil {
		return err
	}

	r, w := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- d.IpcSetOperation(r)
		r.Close()
	}()

	toErr := cfg.ToUAPI(logf, w, prev)
	w.Close()
	setErr := <-errc
	return errors.Join(setErr, toErr)
}
