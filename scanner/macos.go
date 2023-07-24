package scanner

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// inherit OsTypeInterface
type macos struct {
	base
}

func newMacOS(c config.ServerInfo) *macos {
	d := &macos{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	d.log = logging.NewNormalLogger()
	d.setServerInfo(c)
	return d
}

func detectMacOS(c config.ServerInfo) (bool, osTypeInterface) {
	if r := exec(c, "sw_vers", noSudo); r.isSuccess() {
		m := newMacOS(c)
		family, version, err := parseSWVers(r.Stdout)
		if err != nil {
			m.setErrs([]error{xerrors.Errorf("Failed to parse sw_vers. err: %w", err)})
			return true, m
		}
		m.setDistro(family, version)
		return true, m
	}
	return false, nil
}

func parseSWVers(stdout string) (string, string, error) {
	var name, version string
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		t := scanner.Text()
		switch {
		case strings.HasPrefix(t, "ProductName:"):
			name = strings.TrimSpace(strings.TrimPrefix(t, "ProductName:"))
		case strings.HasPrefix(t, "ProductVersion:"):
			version = strings.TrimSpace(strings.TrimPrefix(t, "ProductVersion:"))
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", xerrors.Errorf("Failed to scan by the scanner. err: %w", err)
	}

	var family string
	switch name {
	case "Mac OS X":
		family = constant.MacOSX
	case "Mac OS X Server":
		family = constant.MacOSXServer
	case "macOS":
		family = constant.MacOS
	case "macOS Server":
		family = constant.MacOSServer
	default:
		return "", "", xerrors.Errorf("Failed to detect MacOS Family. err: \"%s\" is unexpected product name", name)
	}

	if version == "" {
		return "", "", xerrors.New("Failed to get ProductVersion string. err: ProductVersion is empty")
	}

	return family, version, nil
}

func (o *macos) checkScanMode() error {
	return nil
}

func (o *macos) checkIfSudoNoPasswd() error {
	return nil
}

func (o *macos) checkDeps() error {
	return nil
}

func (o *macos) preCure() error {
	if err := o.detectIPAddr(); err != nil {
		o.log.Warnf("Failed to detect IP addresses: %s", err)
		o.warns = append(o.warns, err)
	}
	return nil
}

func (o *macos) detectIPAddr() (err error) {
	r := o.exec("/sbin/ifconfig", noSudo)
	if !r.isSuccess() {
		return xerrors.Errorf("Failed to detect IP address: %v", r)
	}
	o.ServerInfo.IPv4Addrs, o.ServerInfo.IPv6Addrs = o.parseIfconfig(r.Stdout)
	if err != nil {
		return xerrors.Errorf("Failed to parse Ifconfig. err: %w", err)
	}
	return nil
}

func (o *macos) postScan() error {
	return nil
}

func (o *macos) scanPackages() error {
	o.log.Infof("Scanning OS pkg in %s", o.getServerInfo().Mode)

	// collect the running kernel information
	release, version, err := o.runningKernel()
	if err != nil {
		o.log.Errorf("Failed to scan the running kernel version: %s", err)
		return err
	}
	o.Kernel = models.Kernel{
		Version: version,
		Release: release,
	}

	installed, err := o.scanInstalledPackages()
	if err != nil {
		return xerrors.Errorf("Failed to scan installed packages. err: %w", err)
	}
	o.Packages = installed

	return nil
}

func (o *macos) scanInstalledPackages() (models.Packages, error) {
	r := o.exec("find -L /Applications /System/Applications -type f -path \"*.app/Contents/Info.plist\" -not -path \"*.app/**/*.app/*\"", noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to exec: %v", r)
	}

	installed := models.Packages{}

	scanner := bufio.NewScanner(strings.NewReader(r.Stdout))
	for scanner.Scan() {
		t := scanner.Text()
		n := filepath.Base(strings.TrimSuffix(t, ".app/Contents/Info.plist"))
		var v string
		if r := o.exec(fmt.Sprintf("plutil -extract \"CFBundleShortVersionString\" raw \"%s\" -o -", t), noSudo); r.isSuccess() {
			v = strings.TrimSpace(r.Stdout)
		}
		installed[n] = models.Package{
			Name:    n,
			Version: v,
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("Failed to scan by the scanner. err: %w", err)
	}

	return installed, nil
}

func (o *macos) parseInstalledPackages(stdout string) (models.Packages, models.SrcPackages, error) {
	pkgs := models.Packages{}
	var p, v string

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		t := scanner.Text()
		if t == "" {
			if p != "" {
				n := filepath.Base(strings.TrimSuffix(p, ".app/Contents/Info.plist"))
				pkgs[n] = models.Package{
					Name:    n,
					Version: v,
				}
			}
			p, v = "", ""
			continue
		}

		lhs, rhs, ok := strings.Cut(t, ":")
		if !ok {
			return nil, nil, xerrors.Errorf("unexpected installed packages line. expected: \"<TAG>: <VALUE>\", actual: \"%s\"", t)
		}

		switch lhs {
		case "Info.plist":
			p = strings.TrimSpace(rhs)
		case "CFBundleShortVersionString":
			v = strings.TrimSpace(rhs)
			if strings.HasSuffix(v, "error: No value at that key path or invalid key path: CFBundleShortVersionString") {
				v = ""
			}
		default:
			return nil, nil, xerrors.Errorf("unexpected installed packages line tag. expected: [\"Info.plist\", \"CFBundleShortVersionString\"], actual: \"%s\"", lhs)
		}

	}
	if p != "" {
		n := filepath.Base(strings.TrimSuffix(p, ".app/Contents/Info.plist"))
		pkgs[n] = models.Package{
			Name:    n,
			Version: v,
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("Failed to scan by the scanner. err: %w", err)
	}

	return pkgs, nil, nil
}
