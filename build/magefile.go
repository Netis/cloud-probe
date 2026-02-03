//go:build mage

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"
)

const (
	distDir = "dist"
	tmpDir  = "tmp"
)

const (
	ENV_CLOUD_PROBE_VERSION      = "CLOUD_PROBE_VERSION"
	ENV_CLOUD_PROBE_PACKAGE_FILE = "CLOUD_PROBE_PACKAGE_FILE"

	ENV_CPWORKER_VERSION              = "CPWORKER_VERSION"
	ENV_CPWORKER_LIBRARY_ROOT         = "CPWORKER_LIBRARY_ROOT"
	ENV_CPWORKER_CMAKE_TOOLCHAIN_FILE = "CPWORKER_CMAKE_TOOLCHAIN_FILE"

	ENV_CPDAEMON_VERSION = "CPDAEMON_VERSION"
	ENV_CPCTL_VERSION    = "CPCTL_VERSION"
)

var allEnvCfg = []string{
	ENV_CLOUD_PROBE_VERSION,
	ENV_CLOUD_PROBE_PACKAGE_FILE,

	ENV_CPWORKER_VERSION,
	ENV_CPWORKER_LIBRARY_ROOT,
	ENV_CPWORKER_CMAKE_TOOLCHAIN_FILE,

	ENV_CPDAEMON_VERSION,
	ENV_CPCTL_VERSION,
}

func getEnvCfg(name string) string {
	return os.Getenv(name)
}

func getEnvCfgE(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("%s is not set", name)
	}
	return value, nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func packageRoot(os string, arch string) string {
	return filepath.Join(distDir, fmt.Sprintf("%s-%s", os, arch), "cloud-probe")
}

func packageBinaryPath(os string, arch string) string {
	return filepath.Join(packageRoot(os, arch), "bin")
}

func packageFile(os_ string, arch string, version string) string {
	if v := getEnvCfg(ENV_CLOUD_PROBE_PACKAGE_FILE); v != "" {
		return v
	}
	return filepath.Join(distDir, fmt.Sprintf("cloud-probe-%s-%s-%s.tar.gz", version, os_, arch))
}

func copyCpworkerExamples(targetDir string) error {
	srcDir := "../cpworker/examples"
	dstDir := filepath.Join(targetDir, "cpworker")
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("create dir %q error: %w", dstDir, err)
	}
	entires, err := os.ReadDir(srcDir)
	if err != nil {
		return errors.Errorf("read directory: %s error", srcDir)
	}
	for _, entry := range entires {
		if entry.IsDir() {
			continue
		}
		if err := copyFile(filepath.Join(srcDir, entry.Name()), filepath.Join(dstDir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyCpdaemonExamples(targetDir string) error {
	srcDir := "../cpdaemon/examples"
	dstDir := filepath.Join(targetDir, "cpdaemon")
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("create dir %q error: %w", dstDir, err)
	}
	entires, err := os.ReadDir(srcDir)
	if err != nil {
		return errors.Errorf("read directory: %s error", srcDir)
	}
	for _, entry := range entires {
		if entry.IsDir() {
			continue
		}
		if err := copyFile(filepath.Join(srcDir, entry.Name()), filepath.Join(dstDir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyExamples(os_ string, arch string) error {
	targetDir := filepath.Join(packageRoot(os_, arch), "examples")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("create dir %q error: %w", targetDir, err)
	}

	if err := copyCpworkerExamples(targetDir); err != nil {
		return err
	}
	if err := copyCpdaemonExamples(targetDir); err != nil {
		return err
	}
	return nil
}

func createPackage(os_ string, arch string, version string) error {
	if err := sh.RunV(
		"tar",
		"-czvf",
		packageFile(os_, arch, version),
		"-C",
		filepath.Join(distDir, fmt.Sprintf("%s-%s", os_, arch)),
		"cloud-probe",
	); err != nil {
		return err
	}
	return nil
}

func runCommand(cmd *exec.Cmd) error {
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	if mg.Verbose() {
		log.Println("exec:", cmd.String())
	}
	return cmd.Run()
}

func Clean() error {
	return sh.Run("rm", "-rf", distDir, tmpDir)
}

func ListEnvCfg() {
	for _, v := range allEnvCfg {
		fmt.Println(v)
	}
}

type GoBuildConfig struct {
	OS               string
	Arch             string
	EnableDebug      bool
	CustomVars       map[string]string
	Env              map[string]string
	EnableCGo        bool
	ModulePath       string
	RootPackagePath  string
	OutputBinaryPath string
}

func newGoBuildConfig(os string, arch string) GoBuildConfig {
	return GoBuildConfig{
		OS:          os,
		Arch:        arch,
		EnableDebug: false,
		CustomVars:  make(map[string]string),
		Env:         make(map[string]string),
	}
}

func buildGoBinary(cfg GoBuildConfig) error {
	outputBinaryPath, err := filepath.Abs(cfg.OutputBinaryPath)
	if err != nil {
		return err
	}

	args := []string{
		"build",
		"-o", outputBinaryPath,
	}

	ldFlags := ""
	if !cfg.EnableCGo {
		// Link statically
		ldFlags = "-extldflags '-static'"
	}

	flags := make(map[string]string)
	for k, v := range cfg.CustomVars {
		flags[k] = v
	}

	flagsKeys := make([]string, 0, len(flags))
	for k := range flags {
		flagsKeys = append(flagsKeys, k)
	}
	sort.Strings(flagsKeys)

	for _, k := range flagsKeys {
		ldFlags = fmt.Sprintf("%s -X %s=%s ", ldFlags, k, flags[k])
	}

	args = append(args, "-ldflags", ldFlags)
	if cfg.EnableDebug {
		args = append(args, "-gcflags=all=-N -l")
	}
	if cfg.RootPackagePath != "" {
		args = append(args, cfg.RootPackagePath)
	}

	cfg.Env["GOOS"] = cfg.OS
	cfg.Env["GOARCH"] = cfg.Arch
	if !cfg.EnableCGo {
		cfg.Env["CGO_ENABLED"] = "0"
	}

	cmd := exec.Command("go", args...)
	cmd.Env = os.Environ()
	for k, v := range cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Dir = cfg.ModulePath
	return runCommand(cmd)
}

func cpdaemonVersion() (string, error) {
	version := getEnvCfg(ENV_CPDAEMON_VERSION)
	if version != "" {
		return version, nil
	}

	version = getEnvCfg(ENV_CLOUD_PROBE_VERSION)
	if version != "" {
		return version, nil
	}

	return "", fmt.Errorf("%s or %s is not set", ENV_CPDAEMON_VERSION, ENV_CLOUD_PROBE_VERSION)
}

func buildCpdaemon(cfg GoBuildConfig) error {
	version, err := cpdaemonVersion()
	if err != nil {
		return err
	}
	cfg.OutputBinaryPath = filepath.Join(packageBinaryPath(cfg.OS, cfg.Arch), "cpdaemon")
	cfg.ModulePath = "../cpdaemon"
	cfg.CustomVars["github.com/Netis/cloud-probe/cpdaemon/pkg/version.Version"] = version
	return buildGoBinary(cfg)
}

type Cpdaemon mg.Namespace

func (Cpdaemon) Linux() error {
	return buildCpdaemon(newGoBuildConfig("linux", "amd64"))
}

func (Cpdaemon) LinuxARM64() error {
	return buildCpdaemon(newGoBuildConfig("linux", "arm64"))
}

func (Cpdaemon) Windows() error {
	return buildCpdaemon(newGoBuildConfig("windows", "amd64"))
}

func (Cpdaemon) Darwin() error {
	return buildCpdaemon(newGoBuildConfig("darwin", "amd64"))
}

func (Cpdaemon) DarwinARM64() error {
	return buildCpdaemon(newGoBuildConfig("darwin", "arm64"))
}

type CBuildConfig struct {
	OS          string
	Arch        string
	ProjectPath string
	BuildPath   string
	Defines     []string
	RunInstall  bool
}

func newCBuildConfig(os string, arch string) CBuildConfig {
	return CBuildConfig{
		OS:   os,
		Arch: arch,
	}
}

func buildCBinary(cfg CBuildConfig) error {
	if err := sh.Run("mkdir", "-p", cfg.BuildPath); err != nil {
		return err
	}

	projectPath, err := filepath.Abs(cfg.ProjectPath)
	if err != nil {
		return err
	}

	args := []string{projectPath}
	for _, define := range cfg.Defines {
		args = append(args, fmt.Sprintf("-D%s", define))
	}

	cmd := exec.Command("cmake", args...)
	cmd.Dir = cfg.BuildPath
	if err := runCommand(cmd); err != nil {
		return err
	}

	cmd = exec.Command("make")
	cmd.Dir = cfg.BuildPath
	if err := runCommand(cmd); err != nil {
		return err
	}

	if cfg.RunInstall {
		cmd = exec.Command("make", "install")
		cmd.Dir = cfg.BuildPath
		if err := runCommand(cmd); err != nil {
			return err
		}
	}
	return nil
}

func cpworkerVersion() (string, error) {
	version := getEnvCfg(ENV_CPWORKER_VERSION)
	if version != "" {
		return version, nil
	}

	version = getEnvCfg(ENV_CLOUD_PROBE_VERSION)
	if version != "" {
		return version, nil
	}

	return "", fmt.Errorf("%s or %s is not set", ENV_CPWORKER_VERSION, ENV_CLOUD_PROBE_VERSION)
}

func buildCpworker(cfg CBuildConfig) error {
	version, err := cpworkerVersion()
	if err != nil {
		return err
	}

	libRoot, err := getEnvCfgE(ENV_CPWORKER_LIBRARY_ROOT)
	if err != nil {
		return err
	}

	installPrefix, _ := filepath.Abs(packageRoot(cfg.OS, cfg.Arch))
	cfg.BuildPath = filepath.Join(tmpDir, fmt.Sprintf("cpworker-%s-%s", cfg.OS, cfg.Arch))
	cfg.ProjectPath = "../cpworker"
	cfg.Defines = append(cfg.Defines,
		fmt.Sprintf("LIBRARY_ROOT=%s", libRoot),
		fmt.Sprintf("CPWORKER_VERSION=%s", version),
		fmt.Sprintf("CMAKE_INSTALL_PREFIX=%s", installPrefix),
	)
	if tc := getEnvCfg(ENV_CPWORKER_CMAKE_TOOLCHAIN_FILE); tc != "" {
		cfg.Defines = append(cfg.Defines, fmt.Sprintf("CMAKE_TOOLCHAIN_FILE=%s", tc))
	}
	cfg.RunInstall = true

	if err := buildCBinary(cfg); err != nil {
		return err
	}
	return nil
}

type Cpworker mg.Namespace

func (Cpworker) Linux() error {
	return buildCpworker(newCBuildConfig("linux", "amd64"))
}

func (Cpworker) LinuxARM64() error {
	return buildCpworker(newCBuildConfig("linux", "arm64"))
}

func (Cpworker) Windows() error {
	return buildCpworker(newCBuildConfig("windows", "amd64"))
}

func (Cpworker) Darwin() error {
	return buildCpworker(newCBuildConfig("darwin", "amd64"))
}

func (Cpworker) DarwinARM64() error {
	return buildCpworker(newCBuildConfig("darwin", "arm64"))
}

func cpctlVersion() (string, error) {
	version := getEnvCfg(ENV_CPCTL_VERSION)
	if version != "" {
		return version, nil
	}

	version = getEnvCfg(ENV_CLOUD_PROBE_VERSION)
	if version != "" {
		return version, nil
	}

	return "", fmt.Errorf("%s or %s is not set", ENV_CPCTL_VERSION, ENV_CLOUD_PROBE_VERSION)
}

func buildCpctl(cfg GoBuildConfig) error {
	version, err := cpctlVersion()
	if err != nil {
		return err
	}
	cfg.OutputBinaryPath = filepath.Join(packageBinaryPath(cfg.OS, cfg.Arch), "cpctl")
	cfg.ModulePath = "../cpctl"
	cfg.CustomVars["github.com/Netis/cloud-probe/cpctl/cmd.Version"] = version
	return buildGoBinary(cfg)
}

type Cpctl mg.Namespace

func (Cpctl) Linux() error {
	return buildCpctl(newGoBuildConfig("linux", "amd64"))
}

func (Cpctl) LinuxARM64() error {
	return buildCpctl(newGoBuildConfig("linux", "arm64"))
}

func (Cpctl) Windows() error {
	return buildCpctl(newGoBuildConfig("windows", "amd64"))
}

func (Cpctl) Darwin() error {
	return buildCpctl(newGoBuildConfig("darwin", "amd64"))
}

func (Cpctl) DarwinARM64() error {
	return buildCpctl(newGoBuildConfig("darwin", "arm64"))
}

func buildDockerPid(cfg GoBuildConfig) error {
	cfg.OutputBinaryPath = filepath.Join(packageBinaryPath(cfg.OS, cfg.Arch), "dockerpid")
	cfg.ModulePath = "../cptools/dockerpid"
	return buildGoBinary(cfg)
}

type DockerPid mg.Namespace

func (DockerPid) Linux() error {
	return buildDockerPid(newGoBuildConfig("linux", "amd64"))
}

func (DockerPid) LinuxARM64() error {
	return buildDockerPid(newGoBuildConfig("linux", "arm64"))
}

func (DockerPid) Windows() error {
	return buildDockerPid(newGoBuildConfig("windows", "amd64"))
}

func (DockerPid) Darwin() error {
	return buildDockerPid(newGoBuildConfig("darwin", "amd64"))
}

func (DockerPid) DarwinARM64() error {
	return buildDockerPid(newGoBuildConfig("darwin", "arm64"))
}

type Make mg.Namespace

func (Make) Linux() error {
	mg.Deps(Cpworker.Linux, Cpdaemon.Linux, Cpctl.Linux, DockerPid.Linux)
	return copyExamples("linux", "amd64")
}

func (Make) LinuxARM64() error {
	mg.Deps(Cpworker.LinuxARM64, Cpdaemon.LinuxARM64, Cpctl.LinuxARM64, DockerPid.LinuxARM64)
	return copyExamples("linux", "arm64")
}

func (Make) Windows() error {
	mg.Deps(Cpworker.Windows, Cpdaemon.Windows, Cpctl.Windows, DockerPid.Windows)
	return copyExamples("windows", "amd64")
}

func (Make) Darwin() error {
	mg.Deps(Cpworker.Darwin, Cpdaemon.Darwin, Cpctl.Darwin, DockerPid.Darwin)
	return copyExamples("darwin", "amd64")
}

func (Make) DarwinARM64() error {
	mg.Deps(Cpworker.DarwinARM64, Cpdaemon.DarwinARM64, Cpctl.DarwinARM64, DockerPid.DarwinARM64)
	return copyExamples("darwin", "arm64")
}

type Build mg.Namespace

func (Build) Linux() error {
	version, err := getEnvCfgE(ENV_CLOUD_PROBE_VERSION)
	if err != nil {
		return err
	}
	mg.Deps(Make.Linux)
	return createPackage("linux", "amd64", version)
}

func (Build) LinuxARM64() error {
	version, err := getEnvCfgE(ENV_CLOUD_PROBE_VERSION)
	if err != nil {
		return err
	}
	mg.Deps(Make.LinuxARM64)
	return createPackage("linux", "arm64", version)
}

func (Build) Windows() error {
	version, err := getEnvCfgE(ENV_CLOUD_PROBE_VERSION)
	if err != nil {
		return err
	}
	mg.Deps(Make.Windows)
	return createPackage("windows", "amd64", version)
}

func (Build) Darwin() error {
	version, err := getEnvCfgE(ENV_CLOUD_PROBE_VERSION)
	if err != nil {
		return err
	}
	mg.Deps(Make.Darwin)
	return createPackage("darwin", "amd64", version)
}

func (Build) DarwinARM64() error {
	version, err := getEnvCfgE(ENV_CLOUD_PROBE_VERSION)
	if err != nil {
		return err
	}
	mg.Deps(Make.DarwinARM64)
	return createPackage("darwin", "arm64", version)
}
