/*
* Copyright (C) 2024  Aleksandr Negashev (i@negash.ru)
 */

package timeweb

import (
	"context"
	"encoding/json"
	"fmt"
	openapi "github.com/GIT_USER_ID/GIT_REPO_ID"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Driver struct {
	*drivers.BaseDriver
	Token string

	ServerID int32
	SshKeyID float32

	ConfigurationId  int
	Disk             int
	Cpu              int
	Ram              int
	IsDdosGuard      bool
	Os               string
	OsId             int
	ImageId          string
	SoftwareId       int
	Preset           string
	PresetId         int
	Bandwidth        int
	AvatarId         string
	Comment          string
	NetworkId        string
	FloatingIp       string
	FloatingIpId     string
	InitData         string
	AvailabilityZone string
}

const (
	flagToken            = "timeweb-cloud-token"
	flagConfigurationId  = "timeweb-configuration-id"
	flagDisk             = "timeweb-disk"
	flagCpu              = "timeweb-cpu"
	flagRam              = "timeweb-ram"
	flagIsDdosGuard      = "timeweb-is-ddos-guard"
	flagOs               = "timeweb-os"
	flagImageId          = "timeweb-image-id"
	flagSoftwareId       = "timeweb-software-id"
	flagPreset           = "timeweb-preset"
	flagBandwidth        = "timeweb-bandwidth"
	flagAvatarId         = "timeweb-avatar-id"
	flagComment          = "timeweb-comment"
	flagNetworkId        = "timeweb-network-id"
	flagFloatingIp       = "timeweb-floating-ip"
	flagInitData         = "timeweb-init-data"
	flagAvailabilityZone = "timeweb-availability-zone"

	defaultSSHPort = 22
	defaultSSHUser = "docker"
)

func NewDriver(hostName, storePath string) drivers.Driver {
	driver := &Driver{
		BaseDriver: &drivers.BaseDriver{
			SSHPort:     defaultSSHPort,
			SSHUser:     defaultSSHUser,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}

	return driver
}

func (d *Driver) DriverName() string {
	return "timeweb"
}

func (d *Driver) getClient() *openapi.APIClient {

	cfg := openapi.NewConfiguration()
	cfg.AddDefaultHeader("Authorization", "Bearer "+d.Token)

	return openapi.NewAPIClient(cfg)
}

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "TIMEWEB_CLOUD_TOKEN",
			Name:   flagToken,
			Usage:  "Project-specific timeweb API cloud token",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "TIMEWEB_IMAGE_ID",
			Name:   flagImageId,
			Usage:  "Image to use for server creation",
			Value:  "",
		},
		mcnflag.IntFlag{
			EnvVar: "TIMEWEB_CONFIGURATION_ID",
			Name:   flagConfigurationId,
			Usage:  "Unique configuration id of server. Cannot be used together with --timeweb-preset",
			Value:  0,
		},
		mcnflag.IntFlag{
			EnvVar: "TIMEWEB_DISK",
			Name:   flagDisk,
			Usage:  "Server disk size in Mb",
		},
		mcnflag.IntFlag{
			EnvVar: "TIMEWEB_CPU",
			Name:   flagCpu,
			Usage:  "Server cpu count",
		},
		mcnflag.IntFlag{
			EnvVar: "TIMEWEB_RAM",
			Name:   flagRam,
			Usage:  "Server ram size in Mb",
		},
		mcnflag.BoolFlag{
			EnvVar: "TIMEWEB_IS_DDOS_GUARD",
			Name:   flagIsDdosGuard,
			Usage:  "DDoS protection. The server is provided with a protected IP address with L3/L4 protection. To enable L7 protection, you need to create a ticket for technical support",
		},
		mcnflag.StringFlag{
			EnvVar: "TIMEWEB_OS",
			Name:   flagOs,
			Usage:  "NAME_VERSION of the operating system that will be installed on the cloud server. Cannot be transmitted together with image_id",
			Value:  "ubuntu_24.04",
		},
		mcnflag.IntFlag{
			EnvVar: "TIMEWEB_SOFTWARE_ID",
			Name:   flagSoftwareId,
			Usage:  "Unique identifier of the server software.",
		},
		mcnflag.StringFlag{
			EnvVar: "TIMEWEB_PRESET",
			Name:   flagPreset,
			Usage:  "Server tariff short name. Cannot be used together with --timeweb-configuration-id",
			Value:  "",
		},
		mcnflag.IntFlag{
			EnvVar: "TIMEWEB_BANDWIDTH",
			Name:   flagBandwidth,
			Usage:  "Tariff bandwidth. Available values are from 100 to 1000 in increments of 100",
			Value:  1000,
		},
		mcnflag.StringFlag{
			EnvVar: "TIMEWEB_AVATAR_ID",
			Name:   flagAvatarId,
			Usage:  "Unique identifier of the server avatar. Description of methods of working with avatars will appear later",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "TIMEWEB_COMMENT",
			Name:   flagComment,
			Usage:  "Unique identifier of the server avatar. Description of methods of working with avatars will appear later",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "TIMEWEB_NETWORK_ID",
			Name:   flagNetworkId,
			Usage:  "Unique network identifier",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "TIMEWEB_FLOATING_IP",
			Name:   flagFloatingIp,
			Usage:  "Use private network",
		},
		mcnflag.StringFlag{
			EnvVar: "TIMEWEB_INIT_DATA",
			Name:   flagInitData,
			Usage:  "Cloud-init script",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "TIMEWEB_AVAILABILITY_ZONE",
			Name:   flagAvailabilityZone,
			Usage:  "Enum: 'spb-1' 'spb-2' 'spb-3' 'spb-4' 'nsk-1' 'ams-1' 'gdn-1' 'ala-1' Availability zone",
			Value:  "spb-1",
		},
	}
}

func (d *Driver) SetConfigFromFlags(opts drivers.DriverOptions) error {

	d.Token = opts.String(flagToken)

	d.Preset = opts.String(flagPreset)

	d.ConfigurationId = opts.Int(flagConfigurationId)
	d.Ram = opts.Int(flagRam)
	d.Cpu = opts.Int(flagCpu)
	d.Disk = opts.Int(flagDisk)

	d.IsDdosGuard = opts.Bool(flagIsDdosGuard)

	d.Os = opts.String(flagOs)
	d.ImageId = opts.String(flagImageId)
	d.Bandwidth = opts.Int(flagBandwidth)
	d.AvatarId = opts.String(flagAvatarId)
	d.Comment = opts.String(flagComment)
	//d.NetworkId = opts.String(flagNetworkId)
	//d.FloatingIp = opts.String(flagFloatingIp)
	//d.AvailabilityZone = flagAvailabilityZone

	d.InitData = opts.String(flagInitData)
	d.SSHUser = "root"
	d.SSHPort = 22

	d.SetSwarmConfigFromFlags(opts)

	return nil
}

func FindOsInApi(OsWithVersion string, client openapi.APIClient) (int, error) {

	arr := strings.Split(OsWithVersion, "_")
	OsName := arr[0]
	OsVersion := arr[1]

	_, err := openapi.NewOSFromValue(OsName)
	if err != nil {
		return 0, err
	}
	// check os version
	OsList, _, err := client.ServersAPI.GetOsList(context.Background()).Execute()
	if err != nil {
		return 0, err
	}

	for _, os := range OsList.ServersOs {
		if OsName == os.GetName() && OsVersion == os.GetVersion() {
			log.Info("Operation system", OsName, OsVersion, "is found")
			return int(os.GetId()), nil
		}
	}

	return 0, fmt.Errorf("OsName %s or OsVersion %s not found", OsName, OsVersion)
}

func (d *Driver) PreCreateCheck() error {
	c := d.getClient()
	ctx := context.Background()
	// TODO check format err
	err := fmt.Errorf("")
	// check os
	d.OsId, err = FindOsInApi(d.Os, *c)
	if err != nil {
		return err
	}
	// check bandwidth
	if d.Bandwidth < 100 || d.Bandwidth > 1000 || d.Bandwidth%100 != 0 {
		return fmt.Errorf("Invalid bandwidth value. Available values are from 100 to 1000 in increments of 100")
	}
	// check VM size
	if d.Preset != "" && d.ConfigurationId != 0 {
		return fmt.Errorf("Only one of --timeweb-preset or --timeweb-configuration-id can be specified")
	}

	if d.ConfigurationId != 0 && d.Preset == "" {
		configOk := false
		configurations, _, _ := c.ServersAPI.GetConfigurators(ctx).Execute()
		for _, configuration := range configurations.ServerConfigurators {
			if d.ConfigurationId == int(configuration.GetId()) {
				configOk = true
				log.Info("Use config ID", d.ConfigurationId, "in", configuration.GetLocation())
				r := configuration.GetRequirements()
				// set default CPU
				if d.Cpu == 0 {
					d.Cpu = int(r.CpuMin)
				}
				if int(r.CpuMin) > d.Cpu || d.Cpu > int(r.CpuMax) && d.Cpu%int(r.CpuStep) != 0 {
					return fmt.Errorf("CPU no in requirements min:%v max:%v step:%v", r.CpuMin, r.CpuMax, r.CpuStep)
				}
				// set default Ram
				if d.Ram == 0 {
					d.Ram = int(r.RamMin)
				}
				if int(r.RamMin) > d.Ram || d.Ram > int(r.RamMax) && d.Ram%int(r.RamStep) != 0 {
					return fmt.Errorf("RAM no in requirements min:%v max:%v step:%v", r.RamMin, r.RamMax, r.RamStep)
				}
				// set default disk
				if d.Disk == 0 {
					d.Disk = int(r.DiskMin)
				}
				if int(r.DiskMin) > d.Disk || d.Disk > int(r.DiskMax) && d.Disk%int(r.DiskStep) != 0 {
					return fmt.Errorf("Disk size no in requirements min:%v max:%v step:%v", r.DiskMin, r.DiskMax, r.DiskStep)
				}
				if int(r.NetworkBandwidthMin) > d.Bandwidth || d.Bandwidth > int(r.NetworkBandwidthStep) && d.Bandwidth%int(r.NetworkBandwidthStep) != 0 {
					return fmt.Errorf("Network Bandwidth no in requirements min:%v max:%v step:%v", r.NetworkBandwidthMin, r.NetworkBandwidthMax, r.NetworkBandwidthStep)
				}
				break
			}
		}
		if !configOk {
			log.Info("Use one of:")
			for _, configuration := range configurations.ServerConfigurators {
				log.Info("id", configuration.GetId(), "location:", configuration.GetLocation())
			}
			return fmt.Errorf("Invalid configuration id %v is not found", strconv.Itoa(d.ConfigurationId))
		}
	} else if d.Preset != "" && d.ConfigurationId == 0 {
		PresetList, _, _ := c.ServersAPI.GetServersPresets(ctx).Execute()
		for _, preset := range PresetList.ServerPresets {
			// find the cheapest rate
			if d.Preset == preset.GetDescriptionShort() {
				log.Info("Use preset", d.Preset)
				d.PresetId = int(preset.GetId())
			}
		}
		if d.PresetId == 0 {
			log.Info("Use one of:")
			for _, preset := range PresetList.ServerPresets {
				log.Info(preset.GetDescriptionShort(), "price:", preset.GetPrice())
			}
			return fmt.Errorf("Preset %s not found", d.Preset)
		}
		log.Debug("Use preset id", d.PresetId)
	} else {
		// use default preset with the cheapest tariff
		price := float32(1000000)
		cheapestPreset := openapi.ServersPreset{}
		PresetList, _, _ := c.ServersAPI.GetServersPresets(ctx).Execute()
		for _, preset := range PresetList.ServerPresets {
			// find the cheapest rate
			presetPrice := preset.GetPrice()
			if presetPrice < price {
				price = presetPrice
				cheapestPreset = preset
			}
		}
		log.Info("Use cheapest preset", cheapestPreset.GetDescriptionShort())
		// set preset
		d.PresetId = int(cheapestPreset.GetId())
		log.Debug("Use preset id", d.PresetId)
	}

	return nil
}

var FixApiCreateKeyRequestResult struct {
	SSHKey struct {
		ID        float32       `json:"id"`
		Body      string        `json:"body"`
		CreatedAt time.Time     `json:"created_at"`
		ExpiredAt interface{}   `json:"expired_at"`
		IsDefault bool          `json:"is_default"`
		Name      string        `json:"name"`
		UsedBy    []interface{} `json:"used_by"`
	} `json:"ssh_key"`
	ResponseID string `json:"response_id"`
}

func (d *Driver) Create() error {
	c := d.getClient()
	ctx := context.Background()
	// generate ssh key
	publicKey, err := d.createSSHKey()
	if err != nil {
		return err
	}
	// add ssh key
	sshKey := openapi.NewCreateKeyRequest(publicKey, false, d.MachineName)
	ApiCreateKeyRequest := c.SSHAPI.CreateKey(ctx)
	_, ResposeKey, err := ApiCreateKeyRequest.CreateKeyRequest(*sshKey).Execute()
	if err != nil {
		return err
	}
	log.Info("Created ssh key", sshKey.Body)
	// config server
	server := openapi.NewCreateServer(d.IsDdosGuard, float32(d.Bandwidth), d.MachineName)
	server.SetOsId(float32(d.OsId))
	// set server size
	if d.ConfigurationId != 0 {
		server.SetConfiguration(openapi.CreateServerConfiguration{
			ConfiguratorId: float32(d.ConfigurationId),
			Disk:           float32(d.Disk),
			Cpu:            float32(d.Cpu),
			Ram:            float32(d.Ram),
		})
	}
	if d.PresetId != 0 {
		server.SetPresetId(float32(d.PresetId))
	}
	// add ssh key to server
	jsonParser := json.NewDecoder(ResposeKey.Body)
	if err = jsonParser.Decode(&FixApiCreateKeyRequestResult); err != nil {
		return err
	}
	d.SshKeyID = FixApiCreateKeyRequestResult.SSHKey.ID
	server.SetSshKeysIds([]float32{FixApiCreateKeyRequestResult.SSHKey.ID})
	// add  cloud init
	server.SetCloudInit(d.InitData)
	// add comment
	server.SetComment(d.Comment)
	// create server
	ApiCreateServerRequest := c.ServersAPI.CreateServer(ctx)
	NewServer, _, err := ApiCreateServerRequest.CreateServer(*server).Execute()
	if err != nil {
		return err
	}
	log.Info("Created server", d.MachineName, "with SSH key", FixApiCreateKeyRequestResult.SSHKey.ID)

	d.ServerID = int32(NewServer.Server.GetId())
	// add ip
	AddServerIPRequest := openapi.NewAddServerIPRequest("ipv4")
	ApiAddServerIPRequest := c.ServersAPI.AddServerIP(ctx, d.ServerID)
	ip, r, err := ApiAddServerIPRequest.AddServerIPRequest(*AddServerIPRequest).Execute()
	if err != nil {
		log.Error("Failed to add server ip", r)
		return err
	}
	FloatingIp := ip.GetServerIp()
	serverIp := FloatingIp.GetIp()
	// get uuid of IP
	log.Info("Get uuid of IP")
	floatingIps, _, err := c.FloatingIPAPI.GetFloatingIps(ctx).Execute()
	if err != nil {
		return err
	}
	for _, floatingIp := range floatingIps.Ips {
		if floatingIp.GetIp() == serverIp {
			d.FloatingIpId = floatingIp.GetId()
		}
	}
	if d.FloatingIpId == "" {
		return fmt.Errorf("FloatingIp not found for server", d.MachineName)
	}
	d.IPAddress = serverIp

	log.Info("Add server ip", serverIp)
	// wait server with GetState
	log.Info("Starting server", d.MachineName, d.ServerID)

	return nil
}

func (d *Driver) createSSHKey() (string, error) {
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return "", err
	}

	publicKey, err := os.ReadFile(d.GetSSHKeyPath() + ".pub")
	if err != nil {
		return "", err
	}

	return string(publicKey), nil
}

func (d *Driver) GetIP() (string, error) {
	return d.IPAddress, nil
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetSSHPort() (int, error) {
	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	return d.SSHUser
}

func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", fmt.Errorf("could not get IP: %w", err)
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil
}

// GetState retrieves the state the machine is currently in; see [drivers.Driver.GetState]
func (d *Driver) GetState() (state.State, error) {
	c := d.getClient()
	ctx := context.Background()
	serverStatus, _, err := c.ServersAPI.GetServer(ctx, d.ServerID).Execute()
	if err != nil {
		return state.None, err
	}
	vmStatus := serverStatus.Server.GetStatus()
	switch vmStatus {
	case "installing":
		return state.Starting, nil
	case "on":
		return state.Running, nil
	case "off":
		return state.Stopped, nil
	}
	return state.None, nil
}

func (d *Driver) Kill() error {
	return d.Remove()
}

func (d *Driver) Remove() error {
	c := d.getClient()
	ctx := context.Background()
	log.Info("Removed server", d.ServerID)
	ApiDeleteServerRequest := c.ServersAPI.DeleteServer(ctx, d.ServerID)
	_, _, err := ApiDeleteServerRequest.Execute()
	if err != nil {
		return err
	}
	// remove IP
	log.Info("Removed IP", d.FloatingIpId)
	ApiDeleteFloatingIPRequest := c.FloatingIPAPI.DeleteFloatingIP(ctx, d.FloatingIpId)
	_, err = ApiDeleteFloatingIPRequest.Execute()
	if err != nil {
		return err
	}
	// remove ssh key
	log.Info("Removed ssh key", d.SshKeyID)
	ApiDeleteKeyRequest := c.SSHAPI.DeleteKey(ctx, int32(d.SshKeyID))
	_, err = ApiDeleteKeyRequest.Execute()
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) Restart() error {
	c := d.getClient()
	ctx := context.Background()
	ApiRebootServerRequest := c.ServersAPI.RebootServer(ctx, d.ServerID)
	_, err := ApiRebootServerRequest.Execute()
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Start() error {
	c := d.getClient()
	ctx := context.Background()
	ApiStartServerRequest := c.ServersAPI.StartServer(ctx, d.ServerID)
	_, err := ApiStartServerRequest.Execute()
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Stop() error {
	c := d.getClient()
	ctx := context.Background()
	ApiShutdownServerRequest := c.ServersAPI.ShutdownServer(ctx, d.ServerID)
	_, err := ApiShutdownServerRequest.Execute()
	if err != nil {
		return err
	}
	return nil
}
