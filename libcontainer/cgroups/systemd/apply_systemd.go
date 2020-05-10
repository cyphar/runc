// +build linux

package systemd

import (
	"bufio"
	stdErrors "errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	systemdDbus "github.com/coreos/go-systemd/dbus"
	"github.com/godbus/dbus"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/devices"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type LegacyManager struct {
	mu      sync.Mutex
	Cgroups *configs.Cgroup
	Paths   map[string]string
}

type subsystem interface {
	// Name returns the name of the subsystem.
	Name() string
	// Returns the stats, as 'stats', corresponding to the cgroup under 'path'.
	GetStats(path string, stats *cgroups.Stats) error
	// Set the cgroup represented by cgroup.
	Set(path string, cgroup *configs.Cgroup) error
}

var errSubsystemDoesNotExist = stdErrors.New("cgroup: subsystem does not exist")

type subsystemSet []subsystem

func (s subsystemSet) Get(name string) (subsystem, error) {
	for _, ss := range s {
		if ss.Name() == name {
			return ss, nil
		}
	}
	return nil, errSubsystemDoesNotExist
}

var legacySubsystems = subsystemSet{
	&fs.CpusetGroup{},
	&fs.DevicesGroup{},
	&fs.MemoryGroup{},
	&fs.CpuGroup{},
	&fs.CpuacctGroup{},
	&fs.PidsGroup{},
	&fs.BlkioGroup{},
	&fs.HugetlbGroup{},
	&fs.PerfEventGroup{},
	&fs.FreezerGroup{},
	&fs.NetPrioGroup{},
	&fs.NetClsGroup{},
	&fs.NameGroup{GroupName: "name=systemd"},
}

const (
	testScopeWait = 4
	testSliceWait = 4
)

func groupPrefix(ruleType configs.DeviceType) (string, error) {
	switch ruleType {
	case configs.BlockDevice:
		return "block-", nil
	case configs.CharDevice:
		return "char-", nil
	default:
		return "", errors.Errorf("device type %v has no group prefix", ruleType)
	}
}

// findDeviceGroup tries to find the device group name (as listed in
// /proc/devices) with the type prefixed as requried for DeviceAllow, for a
// given (type, major) combination. If more than one device group exists, an
// arbitrary one is chosen.
func findDeviceGroup(ruleType configs.DeviceType, ruleMajor int64) (string, error) {
	fh, err := os.Open("/proc/devices")
	if err != nil {
		return "", err
	}
	defer fh.Close()

	prefix, err := groupPrefix(ruleType)
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(fh)
	var currentType configs.DeviceType
	for scanner.Scan() {
		// We need to strip spaces because the first number is column-aligned.
		line := strings.TrimSpace(scanner.Text())

		// Handle the "header" lines.
		switch line {
		case "Block devices:":
			currentType = configs.BlockDevice
			continue
		case "Character devices:":
			currentType = configs.CharDevice
			continue
		case "":
			continue
		}

		// Skip lines unrelated to our type.
		if currentType != ruleType {
			continue
		}

		// Parse out the (major, name).
		var (
			currMajor int64
			currName  string
		)
		if n, err := fmt.Sscanf(line, "%d %s", &currMajor, &currName); err != nil || n != 2 {
			if err == nil {
				err = errors.Errorf("wrong number of fields")
			}
			return "", errors.Wrapf(err, "scan /proc/devices line %q", line)
		}

		if currMajor == ruleMajor {
			return prefix + currName, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", errors.Wrap(err, "reading /proc/devices")
	}
	// Couldn't find the device group.
	return "", nil
}

// generateDeviceProperties takes the configured device rules and generates a
// corresponding set of systemd properties to configure the devices correctly.
func generateDeviceProperties(rules []*configs.DeviceRule) ([]systemdDbus.Property, error) {
	// DeviceAllow is the type "a(ss)" which means we need a temporary struct
	// to represent it in Go.
	type deviceAllowEntry struct {
		Path  string
		Perms string
	}

	properties := []systemdDbus.Property{
		// Always run in the strictest white-list mode.
		newProp("DevicePolicy", "strict"),
		// Empty the DevicesAllow array before filling it.
		newProp("DeviceAllow", []deviceAllowEntry{}),
	}

	// Figure out the set of rules.
	configEmu := &devices.Emulator{}
	for _, rule := range rules {
		if err := configEmu.Apply(*rule); err != nil {
			return nil, errors.Wrap(err, "apply rule for systemd")
		}
	}
	// systemd doesn't support blacklists. So we log a warning, and tell
	// systemd to act as a deny-all whitelist. This ruleset will be replaced
	// with our normal fallback code. This may result in spurrious errors, but
	// the only other option is to error out here.
	if configEmu.IsBlacklist() {
		// However, if we're dealing with an allow-all rule then we can do it.
		if configEmu.IsAllowAll() {
			return []systemdDbus.Property{
				// Run in white-list mode by setting to "auto" and removing all
				// DeviceAllow rules.
				newProp("DevicePolicy", "auto"),
				newProp("DeviceAllow", []deviceAllowEntry{}),
			}, nil
		}
		logrus.Warn("systemd doesn't support blacklist device rules -- applying temporary deny-all rule")
		return properties, nil
	}

	// Now generate the set of rules we actually need to apply. Unlike the
	// normal devices cgroup, in "strict" mode systemd defaults to a deny-all
	// whitelist which is the default for devices.Emulator.
	baseEmu := &devices.Emulator{}
	finalRules, err := baseEmu.Transition(configEmu)
	if err != nil {
		return nil, errors.Wrap(err, "get simplified rules for systemd")
	}
	var deviceAllowList []deviceAllowEntry
	for _, rule := range finalRules {
		if !rule.Allow {
			// Should never happen.
			return nil, errors.Errorf("[internal error] cannot add deny rule to systemd DeviceAllow list: %v", *rule)
		}
		switch rule.Type {
		case configs.BlockDevice, configs.CharDevice:
		default:
			// Should never happen.
			return nil, errors.Errorf("invalid device type for DeviceAllow: %v", rule.Type)
		}

		entry := deviceAllowEntry{
			Perms: string(rule.Permissions),
		}

		// systemd has a fairly odd (though understandable) syntax here, and
		// because of the OCI configuration format we have to do quite a bit of
		// trickery to convert things:
		//
		//  * Concrete rules with non-wildcard major/minor numbers have to use
		//    /dev/{block,char} paths. This is slightly odd because it means
		//    that we cannot add whitelist rules for devices that don't exist,
		//    but there's not too much we can do about that.
		//
		//    However, path globbing is not support for path-based rules so we
		//    need to handle wildcards in some other manner.
		//
		//  * Wildcard-minor rules have to specify a "device group name" (the
		//    second column in /proc/devices).
		//
		//  * Wildcard (major and minor) rules can just specify a glob with the
		//    type ("char-*" or "block-*").
		//
		// The only type of rule we can't handle is wildcard-major rules, and
		// so we'll give a warning in that case (note that the fallback code
		// will insert any rules systemd couldn't handle). What amazing fun.

		if rule.Major == configs.Wildcard {
			// "_ *:n _" rules aren't supported by systemd.
			if rule.Minor != configs.Wildcard {
				logrus.Warnf("systemd doesn't support '*:n' device rules -- temporarily ignoring rule: %v", *rule)
				continue
			}

			// "_ *:* _" rules just wildcard everything.
			prefix, err := groupPrefix(rule.Type)
			if err != nil {
				return nil, err
			}
			entry.Path = prefix + "*"
		} else if rule.Minor == configs.Wildcard {
			// "_ n:* _" rules require a device group from /proc/devices.
			group, err := findDeviceGroup(rule.Type, rule.Major)
			if err != nil {
				return nil, errors.Wrapf(err, "find device '%v/%d'", rule.Type, rule.Major)
			}
			if group == "" {
				// Couldn't find a group.
				logrus.Warnf("could not find device group for '%v/%d' in /proc/devices -- temporarily ignoring rule: %v", rule.Type, rule.Major, *rule)
				continue
			}
			entry.Path = group
		} else {
			// "_ n:m _" rules are just a path in /dev/{block,char}/.
			switch rule.Type {
			case configs.BlockDevice:
				entry.Path = fmt.Sprintf("/dev/block/%d:%d", rule.Major, rule.Minor)
			case configs.CharDevice:
				entry.Path = fmt.Sprintf("/dev/char/%d:%d", rule.Major, rule.Minor)
			}
		}
		deviceAllowList = append(deviceAllowList, entry)
	}

	properties = append(properties, newProp("DeviceAllow", deviceAllowList))
	return properties, nil
}

var (
	connLock sync.Mutex
	theConn  *systemdDbus.Conn
)

func newProp(name string, units interface{}) systemdDbus.Property {
	return systemdDbus.Property{
		Name:  name,
		Value: dbus.MakeVariant(units),
	}
}

// NOTE: This function comes from package github.com/coreos/go-systemd/util
// It was borrowed here to avoid a dependency on cgo.
//
// IsRunningSystemd checks whether the host was booted with systemd as its init
// system. This functions similarly to systemd's `sd_booted(3)`: internally, it
// checks whether /run/systemd/system/ exists and is a directory.
// http://www.freedesktop.org/software/systemd/man/sd_booted.html
func isRunningSystemd() bool {
	fi, err := os.Lstat("/run/systemd/system")
	if err != nil {
		return false
	}
	return fi.IsDir()
}

func UseSystemd() bool {
	if !isRunningSystemd() {
		return false
	}

	connLock.Lock()
	defer connLock.Unlock()

	if theConn == nil {
		var err error
		theConn, err = systemdDbus.New()
		if err != nil {
			return false
		}
	}
	return true
}

func NewSystemdCgroupsManager() (func(config *configs.Cgroup, paths map[string]string) cgroups.Manager, error) {
	if !isRunningSystemd() {
		return nil, fmt.Errorf("systemd not running on this host, can't use systemd as a cgroups.Manager")
	}
	if cgroups.IsCgroup2UnifiedMode() {
		return func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
			return &UnifiedManager{
				Cgroups: config,
				Paths:   paths,
			}
		}, nil
	}
	return func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &LegacyManager{
			Cgroups: config,
			Paths:   paths,
		}
	}, nil
}

func (m *LegacyManager) Apply(pid int) error {
	var (
		c          = m.Cgroups
		unitName   = getUnitName(c)
		slice      = "system.slice"
		properties []systemdDbus.Property
	)

	if c.Paths != nil {
		paths := make(map[string]string)
		for name, path := range c.Paths {
			_, err := getSubsystemPath(m.Cgroups, name)
			if err != nil {
				// Don't fail if a cgroup hierarchy was not found, just skip this subsystem
				if cgroups.IsNotFound(err) {
					continue
				}
				return err
			}
			paths[name] = path
		}
		m.Paths = paths
		return cgroups.EnterPid(m.Paths, pid)
	}

	if c.Parent != "" {
		slice = c.Parent
	}

	properties = append(properties, systemdDbus.PropDescription("libcontainer container "+c.Name))

	// if we create a slice, the parent is defined via a Wants=
	if strings.HasSuffix(unitName, ".slice") {
		properties = append(properties, systemdDbus.PropWants(slice))
	} else {
		// otherwise, we use Slice=
		properties = append(properties, systemdDbus.PropSlice(slice))
	}

	// only add pid if its valid, -1 is used w/ general slice creation.
	if pid != -1 {
		properties = append(properties, newProp("PIDs", []uint32{uint32(pid)}))
	}

	// Check if we can delegate. This is only supported on systemd versions 218 and above.
	if !strings.HasSuffix(unitName, ".slice") {
		// Assume scopes always support delegation.
		properties = append(properties, newProp("Delegate", true))
	}

	// Always enable accounting, this gets us the same behaviour as the fs implementation,
	// plus the kernel has some problems with joining the memory cgroup at a later time.
	properties = append(properties,
		newProp("MemoryAccounting", true),
		newProp("CPUAccounting", true),
		newProp("BlockIOAccounting", true))

	// Assume DefaultDependencies= will always work (the check for it was previously broken.)
	properties = append(properties,
		newProp("DefaultDependencies", false))

	deviceProperties, err := generateDeviceProperties(c.Resources.Devices)
	if err != nil {
		return err
	}
	properties = append(properties, deviceProperties...)

	if c.Resources.Memory != 0 {
		properties = append(properties,
			newProp("MemoryLimit", uint64(c.Resources.Memory)))
	}

	if c.Resources.CpuShares != 0 {
		properties = append(properties,
			newProp("CPUShares", c.Resources.CpuShares))
	}

	// cpu.cfs_quota_us and cpu.cfs_period_us are controlled by systemd.
	if c.Resources.CpuQuota != 0 && c.Resources.CpuPeriod != 0 {
		// corresponds to USEC_INFINITY in systemd
		// if USEC_INFINITY is provided, CPUQuota is left unbound by systemd
		// always setting a property value ensures we can apply a quota and remove it later
		cpuQuotaPerSecUSec := uint64(math.MaxUint64)
		if c.Resources.CpuQuota > 0 {
			// systemd converts CPUQuotaPerSecUSec (microseconds per CPU second) to CPUQuota
			// (integer percentage of CPU) internally.  This means that if a fractional percent of
			// CPU is indicated by Resources.CpuQuota, we need to round up to the nearest
			// 10ms (1% of a second) such that child cgroups can set the cpu.cfs_quota_us they expect.
			cpuQuotaPerSecUSec = uint64(c.Resources.CpuQuota*1000000) / c.Resources.CpuPeriod
			if cpuQuotaPerSecUSec%10000 != 0 {
				cpuQuotaPerSecUSec = ((cpuQuotaPerSecUSec / 10000) + 1) * 10000
			}
		}
		properties = append(properties,
			newProp("CPUQuotaPerSecUSec", cpuQuotaPerSecUSec))
	}

	if c.Resources.BlkioWeight != 0 {
		properties = append(properties,
			newProp("BlockIOWeight", uint64(c.Resources.BlkioWeight)))
	}

	if c.Resources.PidsLimit > 0 {
		properties = append(properties,
			newProp("TasksAccounting", true),
			newProp("TasksMax", uint64(c.Resources.PidsLimit)))
	}

	// We have to set kernel memory here, as we can't change it once
	// processes have been attached to the cgroup.
	if c.Resources.KernelMemory != 0 {
		if err := setKernelMemory(c); err != nil {
			return err
		}
	}

	statusChan := make(chan string, 1)
	if _, err := theConn.StartTransientUnit(unitName, "replace", properties, statusChan); err == nil {
		select {
		case <-statusChan:
		case <-time.After(time.Second):
			logrus.Warnf("Timed out while waiting for StartTransientUnit(%s) completion signal from dbus. Continuing...", unitName)
		}
	} else if !isUnitExists(err) {
		return err
	}

	if err := joinCgroups(c, pid); err != nil {
		return err
	}

	paths := make(map[string]string)
	for _, s := range legacySubsystems {
		subsystemPath, err := getSubsystemPath(m.Cgroups, s.Name())
		if err != nil {
			// Don't fail if a cgroup hierarchy was not found, just skip this subsystem
			if cgroups.IsNotFound(err) {
				continue
			}
			return err
		}
		paths[s.Name()] = subsystemPath
	}
	m.Paths = paths
	return nil
}

func (m *LegacyManager) Destroy() error {
	if m.Cgroups.Paths != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	theConn.StopUnit(getUnitName(m.Cgroups), "replace", nil)
	if err := cgroups.RemovePaths(m.Paths); err != nil {
		return err
	}
	m.Paths = make(map[string]string)
	return nil
}

func (m *LegacyManager) GetPaths() map[string]string {
	m.mu.Lock()
	paths := m.Paths
	m.mu.Unlock()
	return paths
}

func (m *LegacyManager) GetUnifiedPath() (string, error) {
	return "", errors.New("unified path is only supported when running in unified mode")
}

func join(c *configs.Cgroup, subsystem string, pid int) (string, error) {
	path, err := getSubsystemPath(c, subsystem)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(path, 0755); err != nil {
		return "", err
	}
	if err := cgroups.WriteCgroupProc(path, pid); err != nil {
		return "", err
	}
	return path, nil
}

func joinCgroups(c *configs.Cgroup, pid int) error {
	for _, sys := range legacySubsystems {
		name := sys.Name()
		switch name {
		case "name=systemd":
			// let systemd handle this
		case "cpuset":
			path, err := getSubsystemPath(c, name)
			if err != nil && !cgroups.IsNotFound(err) {
				return err
			}
			s := &fs.CpusetGroup{}
			if err := s.ApplyDir(path, c, pid); err != nil {
				return err
			}
		default:
			_, err := join(c, name, pid)
			if err != nil {
				// Even if it's `not found` error, we'll return err
				// because devices cgroup is hard requirement for
				// container security.
				if name == "devices" {
					return err
				}
				// For other subsystems, omit the `not found` error
				// because they are optional.
				if !cgroups.IsNotFound(err) {
					return err
				}
			}
		}
	}

	return nil
}

// systemd represents slice hierarchy using `-`, so we need to follow suit when
// generating the path of slice. Essentially, test-a-b.slice becomes
// /test.slice/test-a.slice/test-a-b.slice.
func ExpandSlice(slice string) (string, error) {
	suffix := ".slice"
	// Name has to end with ".slice", but can't be just ".slice".
	if len(slice) < len(suffix) || !strings.HasSuffix(slice, suffix) {
		return "", fmt.Errorf("invalid slice name: %s", slice)
	}

	// Path-separators are not allowed.
	if strings.Contains(slice, "/") {
		return "", fmt.Errorf("invalid slice name: %s", slice)
	}

	var path, prefix string
	sliceName := strings.TrimSuffix(slice, suffix)
	// if input was -.slice, we should just return root now
	if sliceName == "-" {
		return "/", nil
	}
	for _, component := range strings.Split(sliceName, "-") {
		// test--a.slice isn't permitted, nor is -test.slice.
		if component == "" {
			return "", fmt.Errorf("invalid slice name: %s", slice)
		}

		// Append the component to the path and to the prefix.
		path += "/" + prefix + component + suffix
		prefix += component + "-"
	}
	return path, nil
}

func getSubsystemPath(c *configs.Cgroup, subsystem string) (string, error) {
	mountpoint, err := cgroups.FindCgroupMountpoint(c.Path, subsystem)
	if err != nil {
		return "", err
	}

	initPath, err := cgroups.GetInitCgroup(subsystem)
	if err != nil {
		return "", err
	}
	// if pid 1 is systemd 226 or later, it will be in init.scope, not the root
	initPath = strings.TrimSuffix(filepath.Clean(initPath), "init.scope")

	slice := "system.slice"
	if c.Parent != "" {
		slice = c.Parent
	}

	slice, err = ExpandSlice(slice)
	if err != nil {
		return "", err
	}

	return filepath.Join(mountpoint, initPath, slice, getUnitName(c)), nil
}

func (m *LegacyManager) Freeze(state configs.FreezerState) error {
	path, err := getSubsystemPath(m.Cgroups, "freezer")
	if err != nil {
		return err
	}
	prevState := m.Cgroups.Resources.Freezer
	m.Cgroups.Resources.Freezer = state
	freezer, err := legacySubsystems.Get("freezer")
	if err != nil {
		return err
	}
	err = freezer.Set(path, m.Cgroups)
	if err != nil {
		m.Cgroups.Resources.Freezer = prevState
		return err
	}
	return nil
}

func (m *LegacyManager) GetPids() ([]int, error) {
	path, err := getSubsystemPath(m.Cgroups, "devices")
	if err != nil {
		return nil, err
	}
	return cgroups.GetPids(path)
}

func (m *LegacyManager) GetAllPids() ([]int, error) {
	path, err := getSubsystemPath(m.Cgroups, "devices")
	if err != nil {
		return nil, err
	}
	return cgroups.GetAllPids(path)
}

func (m *LegacyManager) GetStats() (*cgroups.Stats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stats := cgroups.NewStats()
	for name, path := range m.Paths {
		sys, err := legacySubsystems.Get(name)
		if err == errSubsystemDoesNotExist || !cgroups.PathExists(path) {
			continue
		}
		if err := sys.GetStats(path, stats); err != nil {
			return nil, err
		}
	}

	return stats, nil
}

func (m *LegacyManager) Set(container *configs.Config) error {
	// If Paths are set, then we are just joining cgroups paths
	// and there is no need to set any values.
	if m.Cgroups.Paths != nil {
		return nil
	}
	for _, sys := range legacySubsystems {
		// Get the subsystem path, but don't error out for not found cgroups.
		path, err := getSubsystemPath(container.Cgroups, sys.Name())
		if err != nil && !cgroups.IsNotFound(err) {
			return err
		}
		if err := sys.Set(path, container.Cgroups); err != nil {
			return err
		}
	}

	if m.Paths["cpu"] != "" {
		if err := fs.CheckCpushares(m.Paths["cpu"], container.Cgroups.Resources.CpuShares); err != nil {
			return err
		}
	}
	return nil
}

func getUnitName(c *configs.Cgroup) string {
	// by default, we create a scope unless the user explicitly asks for a slice.
	if !strings.HasSuffix(c.Name, ".slice") {
		return fmt.Sprintf("%s-%s.scope", c.ScopePrefix, c.Name)
	}
	return c.Name
}

func setKernelMemory(c *configs.Cgroup) error {
	path, err := getSubsystemPath(c, "memory")
	if err != nil && !cgroups.IsNotFound(err) {
		return err
	}

	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	// do not try to enable the kernel memory if we already have
	// tasks in the cgroup.
	content, err := ioutil.ReadFile(filepath.Join(path, "tasks"))
	if err != nil {
		return err
	}
	if len(content) > 0 {
		return nil
	}
	return fs.EnableKernelMemoryAccounting(path)
}

// isUnitExists returns true if the error is that a systemd unit already exists.
func isUnitExists(err error) bool {
	if err != nil {
		if dbusError, ok := err.(dbus.Error); ok {
			return strings.Contains(dbusError.Name, "org.freedesktop.systemd1.UnitExists")
		}
	}
	return false
}

func (m *LegacyManager) GetCgroups() (*configs.Cgroup, error) {
	return m.Cgroups, nil
}

func (m *LegacyManager) GetFreezerState() (configs.FreezerState, error) {
	path, err := getSubsystemPath(m.Cgroups, "freezer")
	if err != nil && !cgroups.IsNotFound(err) {
		return configs.Undefined, err
	}
	freezer, err := legacySubsystems.Get("freezer")
	if err != nil {
		return configs.Undefined, err
	}
	return freezer.(*fs.FreezerGroup).GetState(path)
}
