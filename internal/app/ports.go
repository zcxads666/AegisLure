package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/config"
)

type portMoveRequest struct {
	BindAddr         string `json:"bind_addr"`
	Port             int    `json:"port"`
	Protocol         string `json:"protocol"`
	DrainSeconds     int    `json:"drain_seconds"`
	ExpectedRevision string `json:"expected_revision"`
}

type portMoveResult struct {
	Profile             string `json:"profile"`
	CurrentPort         int    `json:"current_port"`
	DesiredPort         int    `json:"desired_port"`
	Revision            string `json:"revision"`
	DesiredRevision     string `json:"desired_revision"`
	InApprovedPool      bool   `json:"in_approved_pool"`
	Running             bool   `json:"running"`
	Applied             bool   `json:"applied"`
	RollbackOnFailure   bool   `json:"rollback_on_failure"`
	RestartRequired     bool   `json:"restart_required"`
	DrainSeconds        int    `json:"drain_seconds"`
	HostMappingRequired bool   `json:"host_mapping_required"`
}

func (a *App) portRevisionLocked(profile string, port int) string {
	return config.KeyedHash(a.cfg.InstanceKey, fmt.Sprintf("listener:%s:%d", profile, port))[:16]
}

func (a *App) actualProfilePortLocked(profile string) int {
	if listener := a.profilePorts[profile]; listener != nil {
		if address, ok := listener.Addr().(*net.TCPAddr); ok && address.Port > 0 {
			return address.Port
		}
	}
	return a.cfg.ProfilePorts[profile]
}

func (a *App) validatePortMoveLocked(profile string, request portMoveRequest) (int, error) {
	if _, ok := a.profiles[profile]; !ok {
		return 0, errors.New("profile not found")
	}
	if request.Port < 1 || request.Port > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	if request.BindAddr != "" && request.BindAddr != a.cfg.PublicBind {
		return 0, errors.New("bind_addr must match the configured public bind")
	}
	protocol := strings.ToLower(strings.TrimSpace(request.Protocol))
	if protocol != "" && protocol != "tcp" && protocol != "http" {
		return 0, errors.New("protocol must be tcp or http")
	}
	drain := request.DrainSeconds
	if drain == 0 {
		drain = 30
	}
	if drain < 30 || drain > 120 {
		return 0, errors.New("drain_seconds must be between 30 and 120")
	}
	if !config.PortInPool(a.cfg, profile, request.Port) {
		return 0, errors.New("requested port is outside the approved port pool")
	}
	if request.Port == a.cfg.AdminPort {
		return 0, errors.New("requested port conflicts with the admin port")
	}
	for name, current := range a.cfg.ProfilePorts {
		if name != profile && current == request.Port {
			return 0, errors.New("requested port conflicts with another profile")
		}
	}
	for name, listener := range a.profilePorts {
		if name == profile || listener == nil {
			continue
		}
		if address, ok := listener.Addr().(*net.TCPAddr); ok && address.Port == request.Port {
			return 0, errors.New("requested port is already actively bound")
		}
	}
	current := a.actualProfilePortLocked(profile)
	if request.ExpectedRevision != "" && request.ExpectedRevision != a.portRevisionLocked(profile, current) {
		return 0, errors.New("port revision is stale")
	}
	return drain, nil
}

func (a *App) moveProfilePort(profile string, request portMoveRequest, dryRun bool) (portMoveResult, error) {
	a.serverMu.Lock()
	current := a.actualProfilePortLocked(profile)
	drain, err := a.validatePortMoveLocked(profile, request)
	if err != nil {
		a.serverMu.Unlock()
		return portMoveResult{}, err
	}
	result := portMoveResult{Profile: profile, CurrentPort: current, DesiredPort: request.Port, Revision: a.portRevisionLocked(profile, current), DesiredRevision: a.portRevisionLocked(profile, request.Port), InApprovedPool: true, Running: a.profileServers[profile] != nil, Applied: false, RollbackOnFailure: true, RestartRequired: false, DrainSeconds: drain, HostMappingRequired: false}
	if request.Port == current {
		result.Applied = !dryRun
		a.serverMu.Unlock()
		return result, nil
	}
	if dryRun {
		result.RestartRequired = !result.Running
		a.serverMu.Unlock()
		return result, nil
	}

	oldServer := a.profileServers[profile]
	oldListener := a.profilePorts[profile]
	oldProfile := a.profiles[profile]
	if oldServer == nil {
		a.cfg.ProfilePorts[profile] = request.Port
		profileValue := a.profiles[profile]
		profileValue.DefaultPort = request.Port
		a.profiles[profile] = profileValue
		if err := config.Save(configPathForApp(), a.cfg); err != nil {
			a.cfg.ProfilePorts[profile] = current
			profileValue.DefaultPort = current
			a.profiles[profile] = profileValue
			a.serverMu.Unlock()
			return portMoveResult{}, fmt.Errorf("save port configuration: %w", err)
		}
		result.Applied = true
		result.RestartRequired = true
		a.serverMu.Unlock()
		return result, nil
	}

	newListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", a.cfg.PublicBind, request.Port))
	if err != nil {
		a.serverMu.Unlock()
		return portMoveResult{}, fmt.Errorf("bind replacement listener: %w", err)
	}
	profileValue := a.profiles[profile]
	profileValue.DefaultPort = request.Port
	newServer := &http.Server{Addr: fmt.Sprintf("%s:%d", a.cfg.PublicBind, request.Port), Handler: a.publicHandler(profileValue), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 * 1024}
	a.profileServers[profile] = newServer
	a.profilePorts[profile] = newListener
	a.cfg.ProfilePorts[profile] = request.Port
	a.profiles[profile] = profileValue
	if err := config.Save(configPathForApp(), a.cfg); err != nil {
		a.profileServers[profile] = oldServer
		_ = newListener.Close()
		a.profilePorts[profile] = oldListener
		a.cfg.ProfilePorts[profile] = current
		a.profiles[profile] = oldProfile
		a.serverMu.Unlock()
		return portMoveResult{}, fmt.Errorf("save port configuration: %w", err)
	}
	go a.serve(newServer, newListener, false)
	a.serverMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(drain+5)*time.Second)
	shutdownErr := oldServer.Shutdown(ctx)
	cancel()
	if shutdownErr != nil {
		// The old listener remains the last-known-good state if draining fails.
		_ = oldServer.Close()
		rollbackListener, rollbackErr := net.Listen("tcp", fmt.Sprintf("%s:%d", a.cfg.PublicBind, current))
		a.serverMu.Lock()
		if a.profileServers[profile] == newServer {
			if rollbackErr == nil {
				rollbackServer := &http.Server{Addr: fmt.Sprintf("%s:%d", a.cfg.PublicBind, current), Handler: a.publicHandler(oldProfile), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 32 * 1024}
				a.profileServers[profile] = rollbackServer
				a.profilePorts[profile] = rollbackListener
				go a.serve(rollbackServer, rollbackListener, false)
				a.cfg.ProfilePorts[profile] = current
				a.profiles[profile] = oldProfile
				_ = config.Save(configPathForApp(), a.cfg)
			} else {
				_ = newServer.Shutdown(context.Background())
			}
		}
		a.serverMu.Unlock()
		_ = newServer.Shutdown(context.Background())
		if rollbackErr != nil {
			return portMoveResult{}, fmt.Errorf("drain old listener: %w; rollback listener: %v", shutdownErr, rollbackErr)
		}
		return portMoveResult{}, fmt.Errorf("drain old listener: %w; previous listener restored", shutdownErr)
	}
	result.Applied = true
	return result, nil
}
