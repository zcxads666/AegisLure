package main

import (
	"archive/zip"
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/importer"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/security"
	"github.com/zcxads666/AegisLure/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "init":
		initCommand(os.Args[2:])
	case "status", "health":
		if os.Args[1] == "health" {
			healthCommand(os.Args[2:])
		} else {
			statusCommand(os.Args[2:])
		}
	case "start", "stop", "restart":
		composeLifecycle(os.Args[1], os.Args[2:])
	case "admin":
		adminCommand(os.Args[2:])
	case "backup":
		backupCommand(os.Args[2:])
	case "restore":
		restoreCommand(os.Args[2:])
	case "logs":
		logsCommand(os.Args[2:])
	case "import":
		importCommand(os.Args[2:])
	case "upgrade", "rollback":
		imageCommand(os.Args[1], os.Args[2:])
	case "uninstall":
		uninstallCommand(os.Args[2:])
	case "ports":
		portsCommand(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`hpctl commands:
  init [--config config.json] [--data-dir data]
  status [--config config.json]
  health [--config config.json]
  start|stop|restart [--project-dir .]
	admin entry rotate [--config config.json]
	admin reset issue --user owner [--config config.json]
  backup --output backup.zip [--config config.json]
  restore --input backup.zip [--config config.json] [--data-dir data]
  logs [--data-dir data] [--lines 100]
	import --input events.jsonl --product ollama [--source-id promptpot] [--file-id name] [--schema-version v1]
  ports plan [--config config.json] [--profile name --port port --output plan.json]
	ports apply --input plan.json [--config config.json] [--project-dir .]
  upgrade --image registry.example/aegislure@sha256:... [--project-dir .]
  rollback --image registry.example/aegislure@sha256:... [--project-dir .]
  uninstall [--project-dir .] [--purge-data --confirm-purge]`)
}

func initCommand(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configPath := fs.String("config", "./config.json", "runtime config path")
	dataDir := fs.String("data-dir", "./data", "state and event directory")
	_ = fs.Parse(args)
	if err := os.MkdirAll(*dataDir, 0700); err != nil {
		fatal(err)
	}
	cfg, err := config.Init(*configPath, *dataDir)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("AegisLure initialized\ninstance_id=%s\nadmin_port=%d\nadmin_path=%s\n", cfg.InstanceID, cfg.AdminPort, cfg.AdminPath)
	fmt.Println("Open the admin path to create the first owner account.")
}

func loadConfig(fs *flag.FlagSet) *config.Config {
	path := fs.Lookup("config").Value.String()
	cfg, err := config.Load(path)
	if err != nil {
		fatal(err)
	}
	return cfg
}

func storeOptions(cfg *config.Config) store.Options {
	return store.Options{
		MaxEvents:      cfg.EventMaxEntries,
		EventRetention: time.Duration(cfg.EventRetentionDays) * 24 * time.Hour,
	}
}

func statusCommand(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	fs.String("config", "./config.json", "runtime config path")
	_ = fs.Parse(args)
	cfg := loadConfig(fs)
	st, err := store.OpenWithOptions(cfg.DataDir, cfg.InstanceKey, storeOptions(cfg))
	if err != nil {
		fatal(err)
	}
	scheme := "http"
	certPath := strings.TrimSpace(os.Getenv("HP_TLS_CERT"))
	keyPath := strings.TrimSpace(os.Getenv("HP_TLS_KEY"))
	if certPath == "" {
		certPath = filepath.Join(filepath.Dir(fs.Lookup("config").Value.String()), "secrets", "admin.crt")
	}
	if keyPath == "" {
		keyPath = filepath.Join(filepath.Dir(fs.Lookup("config").Value.String()), "secrets", "admin.key")
	}
	if cfg.RequireAdminTLS || fileExists(certPath) && fileExists(keyPath) {
		scheme = "https"
	}
	result := map[string]any{"instance_id": cfg.InstanceID, "admin_port": cfg.AdminPort, "admin_path_configured": cfg.AdminPath != "", "admin_url": fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, cfg.AdminPort, cfg.AdminPath), "require_admin_tls": cfg.RequireAdminTLS, "enabled_profiles": cfg.EnabledProfiles, "admin_initialized": st.Admin().Initialized, "data_dir": cfg.DataDir, "database_path": st.DatabasePath(), "sqlite_wal": true}
	_ = st.Close()
	printJSON(result)
}

func healthCommand(args []string) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	fs.String("config", "./config.json", "runtime config path")
	host := fs.String("host", "", "Host header allowed by the admin listener; defaults to the first configured allowlist entry or 127.0.0.1")
	_ = fs.Parse(args)
	cfg := loadConfig(fs)
	scheme := "http"
	certPath := os.Getenv("HP_TLS_CERT")
	keyPath := os.Getenv("HP_TLS_KEY")
	if certPath == "" {
		certPath = filepath.Join(filepath.Dir(fs.Lookup("config").Value.String()), "secrets", "admin.crt")
	}
	if keyPath == "" {
		keyPath = filepath.Join(filepath.Dir(fs.Lookup("config").Value.String()), "secrets", "admin.key")
	}
	if cfg.RequireAdminTLS || fileExists(certPath) && fileExists(keyPath) {
		scheme = "https"
	}
	transport := &http.Transport{Proxy: nil}
	if scheme == "https" {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // local self-signed install certificate
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint := fmt.Sprintf("%s://127.0.0.1:%d%sadmin/api/v1/health", scheme, cfg.AdminPort, cfg.AdminPath)
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		fatal(fmt.Errorf("health request failed: %w", err))
	}
	request.Host = strings.TrimSpace(*host)
	if request.Host == "" {
		if len(cfg.AdminHostAllowlist) > 0 {
			request.Host = cfg.AdminHostAllowlist[0]
		} else {
			request.Host = "127.0.0.1"
		}
	}
	response, err := client.Do(request)
	if err != nil {
		fatal(fmt.Errorf("health check failed: %w", err))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fatal(fmt.Errorf("health check returned HTTP %d", response.StatusCode))
	}
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		fatal(fmt.Errorf("health response is invalid: %w", err))
	}
	result["healthy"] = true
	result["endpoint"] = endpoint
	printJSON(result)
}

func composeLifecycle(action string, args []string) {
	fs := flag.NewFlagSet(action, flag.ExitOnError)
	projectDir := fs.String("project-dir", ".", "Compose project directory")
	_ = fs.Parse(args)
	var composeArgs []string
	switch action {
	case "start":
		composeArgs = []string{"up", "-d"}
	case "stop":
		composeArgs = []string{"stop"}
	case "restart":
		composeArgs = []string{"restart"}
	default:
		fatal(errors.New("unsupported lifecycle action"))
	}
	runDockerCompose(*projectDir, composeArgs, "")
}

func imageCommand(action string, args []string) {
	fs := flag.NewFlagSet(action, flag.ExitOnError)
	image := fs.String("image", "", "immutable image reference, preferably registry/name@sha256:digest")
	projectDir := fs.String("project-dir", ".", "Compose project directory")
	pull := fs.Bool("pull", true, "pull the image before starting")
	_ = fs.Parse(args)
	if !validImageReference(*image) {
		fatal(errors.New("--image must be a safe immutable image reference containing @sha256:"))
	}
	if action == "upgrade" && *pull {
		runDockerCompose(*projectDir, []string{"pull"}, *image)
	}
	runDockerCompose(*projectDir, []string{"up", "-d", "--no-build"}, *image)
	fmt.Printf("%s applied image=%s\n", action, *image)
}

func uninstallCommand(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	projectDir := fs.String("project-dir", ".", "Compose project directory")
	configPath := fs.String("config", "./runtime/config.json", "runtime config path")
	purge := fs.Bool("purge-data", false, "delete the configured data and secret directories")
	confirm := fs.Bool("confirm-purge", false, "confirm irreversible data deletion")
	_ = fs.Parse(args)
	if *purge && !*confirm {
		fatal(errors.New("--purge-data requires --confirm-purge"))
	}
	runDockerCompose(*projectDir, []string{"down", "--remove-orphans"}, "")
	if !*purge {
		fmt.Println("AegisLure stopped; runtime data and secrets were retained.")
		return
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	for _, path := range []string{cfg.DataDir, filepath.Join(filepath.Dir(*configPath), "secrets"), *configPath} {
		if path == "" || path == "." || path == string(filepath.Separator) {
			fatal(fmt.Errorf("refusing to purge unsafe path %q", path))
		}
		if err := os.RemoveAll(path); err != nil {
			fatal(err)
		}
	}
	fmt.Println("AegisLure stopped and explicitly confirmed runtime data was removed.")
}

func runDockerCompose(projectDir string, args []string, image string) {
	if filepath.IsAbs(projectDir) == false {
		absolute, err := filepath.Abs(projectDir)
		if err != nil {
			fatal(err)
		}
		projectDir = absolute
	}
	command := exec.Command("docker", append([]string{"compose"}, args...)...)
	command.Dir = projectDir
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if image != "" {
		command.Env = append(os.Environ(), "HP_IMAGE="+image)
	}
	if err := command.Run(); err != nil {
		fatal(fmt.Errorf("docker compose %v: %w", args, err))
	}
}

var imageReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@:-]*@sha256:[a-fA-F0-9]{64}$`)

func validImageReference(value string) bool {
	return imageReferencePattern.MatchString(strings.TrimSpace(value))
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func adminCommand(args []string) {
	if len(args) < 2 {
		usage()
		return
	}
	switch args[0] {
	case "entry":
		if args[1] == "rotate" {
			adminEntryRotate(args[2:])
			return
		}
	case "reset":
		if args[1] == "issue" {
			adminResetIssue(args[2:])
			return
		}
	}
	usage()
}

func adminEntryRotate(args []string) {
	fs := flag.NewFlagSet("admin entry rotate", flag.ExitOnError)
	configPath := fs.String("config", "./config.json", "runtime config path")
	_ = fs.Parse(args)
	cfg := loadConfig(fs)
	token, err := security.RandomToken(18)
	if err != nil {
		fatal(err)
	}
	cfg.AdminPath = "/" + token + "/"
	if err := config.Save(*configPath, cfg); err != nil {
		fatal(err)
	}
	if err := appendCLIAudit(cfg, "admin.entry.rotate", "admin", "success", map[string]string{"path_fp": security.Fingerprint(cfg.InstanceKey, cfg.AdminPath)[:20]}); err != nil {
		fatal(err)
	}
	fmt.Printf("admin_path=%s\nadmin_port=%d\nrestart the service before using the new entry path\n", cfg.AdminPath, cfg.AdminPort)
}

func adminResetIssue(args []string) {
	fs := flag.NewFlagSet("admin reset issue", flag.ExitOnError)
	fs.String("config", "./config.json", "runtime config path")
	username := fs.String("user", "", "owner username")
	_ = fs.Parse(args)
	if strings.TrimSpace(*username) == "" {
		fatal(errors.New("--user is required"))
	}
	cfg := loadConfig(fs)
	st, err := store.OpenWithOptions(cfg.DataDir, cfg.InstanceKey, storeOptions(cfg))
	if err != nil {
		fatal(err)
	}
	defer st.Close()
	admin := st.Admin()
	if !admin.Initialized || admin.OwnerUsername != *username {
		fatal(errors.New("owner not found"))
	}
	code, err := security.RandomToken(32)
	if err != nil {
		fatal(err)
	}
	if err := st.Update(func(state *model.State) error {
		now := time.Now().UTC()
		state.Admin.RescueCodes = append(state.Admin.RescueCodes, model.AdminRecoveryCode{
			Hash:      config.KeyedHash(cfg.InstanceKey, code),
			IssuedAt:  now,
			ExpiresAt: now.Add(10 * time.Minute),
		})
		return nil
	}); err != nil {
		fatal(err)
	}
	if err := st.AppendAudit(model.AuditEntry{Actor: "local_cli", Action: "admin.recovery.issue", Target: "admin", Result: "success", Metadata: map[string]string{"username_fp": security.Fingerprint(cfg.InstanceKey, *username)[:20]}}); err != nil {
		fatal(err)
	}
	fmt.Printf("recovery_code=%s\nexpires_in=600\n", code)
	fmt.Println("Use this code once with auth/recovery-code/reset to replace the owner password.")
}

func appendCLIAudit(cfg *config.Config, action, target, result string, metadata map[string]string) error {
	if cfg == nil || cfg.DataDir == "" || cfg.InstanceKey == "" {
		return errors.New("audit requires a complete runtime config")
	}
	st, err := store.OpenWithOptions(cfg.DataDir, cfg.InstanceKey, storeOptions(cfg))
	if err != nil {
		return err
	}
	defer st.Close()
	return st.AppendAudit(model.AuditEntry{Actor: "local_cli", Action: action, Target: target, Result: result, Metadata: metadata})
}

func backupCommand(args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	configPath := fs.String("config", "./config.json", "runtime config path")
	output := fs.String("output", "aegislure-backup.zip", "backup archive")
	_ = fs.Parse(args)
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	st, err := store.OpenWithOptions(cfg.DataDir, cfg.InstanceKey, storeOptions(cfg))
	if err != nil {
		fatal(err)
	}
	defer st.Close()
	stage, err := os.MkdirTemp(cfg.DataDir, ".aegislure-backup-")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(stage)
	databaseSnapshot := filepath.Join(stage, "aegislure.sqlite")
	if err := st.BackupTo(databaseSnapshot); err != nil {
		fatal(err)
	}
	files := []string{*configPath, databaseSnapshot, filepath.Join(cfg.DataDir, "state.json"), filepath.Join(cfg.DataDir, "events.jsonl")}
	for _, inputPath := range []string{*configPath, filepath.Join(cfg.DataDir, "state.json"), filepath.Join(cfg.DataDir, "events.jsonl")} {
		if sameFilePath(*output, inputPath) {
			fatal(errors.New("backup output must differ from runtime files"))
		}
	}
	archive, err := os.OpenFile(*output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		fatal(err)
	}
	defer archive.Close()
	zw := zip.NewWriter(archive)
	for _, name := range files {
		if err := addFile(zw, name); err != nil && !os.IsNotExist(err) {
			fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		fatal(err)
	}
	if err := archive.Sync(); err != nil {
		fatal(err)
	}
	fmt.Printf("backup=%s\n", *output)
}

func restoreCommand(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	input := fs.String("input", "", "backup archive")
	configPath := fs.String("config", "./config.json", "destination runtime config path")
	dataDir := fs.String("data-dir", "./data", "destination state and event directory")
	_ = fs.Parse(args)
	if strings.TrimSpace(*input) == "" {
		fatal(errors.New("--input is required"))
	}
	archive, err := zip.OpenReader(*input)
	if err != nil {
		fatal(err)
	}
	defer archive.Close()
	if err := os.MkdirAll(filepath.Dir(*configPath), 0700); err != nil {
		fatal(err)
	}
	stage, err := os.MkdirTemp(filepath.Dir(*configPath), ".aegislure-restore-")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(stage)
	allowed := map[string]bool{"config.json": true, "aegislure.sqlite": true, "state.json": true, "events.jsonl": true}
	seenEntries := make(map[string]bool, len(allowed))
	var total int64
	for _, file := range archive.File {
		name := filepath.ToSlash(file.Name)
		if filepath.Base(name) != name || !allowed[name] || file.FileInfo().IsDir() {
			fatal(fmt.Errorf("unsafe or unsupported backup entry %q", file.Name))
		}
		if seenEntries[name] {
			fatal(fmt.Errorf("duplicate backup entry %q", file.Name))
		}
		seenEntries[name] = true
		if file.UncompressedSize64 > 64*1024*1024 || total+int64(file.UncompressedSize64) > 128*1024*1024 {
			fatal(errors.New("backup exceeds restore size limits"))
		}
		r, err := file.Open()
		if err != nil {
			fatal(err)
		}
		out, err := os.OpenFile(filepath.Join(stage, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			r.Close()
			fatal(err)
		}
		written, copyErr := io.Copy(out, io.LimitReader(r, 64*1024*1024+1))
		closeErr := out.Close()
		r.Close()
		if copyErr != nil || closeErr != nil || written > 64*1024*1024 {
			fatal(errors.New("failed to extract backup safely"))
		}
		total += written
	}
	stagedConfig := filepath.Join(stage, "config.json")
	cfg, err := config.Load(stagedConfig)
	if err != nil {
		fatal(fmt.Errorf("invalid backup config: %w", err))
	}
	if cfg.InstanceKey == "" || cfg.InstanceID == "" || cfg.AdminPath == "" {
		fatal(errors.New("backup config is incomplete"))
	}
	stagedDatabase := filepath.Join(stage, "aegislure.sqlite")
	databasePresent := false
	statePresent := false
	eventsPresent := false
	for _, name := range []string{"state.json", "events.jsonl"} {
		if _, statErr := os.Stat(filepath.Join(stage, name)); statErr == nil {
			if name == "state.json" {
				statePresent = true
			} else {
				eventsPresent = true
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			fatal(fmt.Errorf("inspect staged backup entry %s: %w", name, statErr))
		}
	}
	if _, statErr := os.Stat(stagedDatabase); statErr == nil {
		databasePresent = true
		verificationDir, verifyErr := os.MkdirTemp(stage, ".db-verify-")
		if verifyErr != nil {
			fatal(verifyErr)
		}
		if err := copyFileAtomic(stagedDatabase, filepath.Join(verificationDir, "aegislure.sqlite"), 0600); err != nil {
			_ = os.RemoveAll(verificationDir)
			fatal(fmt.Errorf("invalid backup sqlite database: %w", err))
		}
		verifiedStore, verifyErr := store.OpenWithOptions(verificationDir, cfg.InstanceKey, storeOptions(cfg))
		if verifyErr != nil {
			_ = os.RemoveAll(verificationDir)
			fatal(fmt.Errorf("invalid backup sqlite database: %w", verifyErr))
		}
		if closeErr := verifiedStore.Close(); closeErr != nil {
			_ = os.RemoveAll(verificationDir)
			fatal(fmt.Errorf("close backup sqlite verification: %w", closeErr))
		}
		if err := os.RemoveAll(verificationDir); err != nil {
			fatal(fmt.Errorf("remove sqlite verification files: %w", err))
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		fatal(fmt.Errorf("inspect backup sqlite database: %w", statErr))
	}
	if !databasePresent && !statePresent && !eventsPresent {
		fatal(errors.New("backup contains neither sqlite database nor legacy state/event data"))
	}
	if err := os.MkdirAll(*dataDir, 0700); err != nil {
		fatal(err)
	}
	for _, name := range []string{"state.json", "events.jsonl"} {
		source := filepath.Join(stage, name)
		if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
			continue
		}
		destination := filepath.Join(*dataDir, name)
		if err := copyFileAtomic(source, destination, 0600); err != nil {
			fatal(err)
		}
	}
	cfg.DataDir = *dataDir
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if !databasePresent || suffix != "" {
			if err := os.Remove(filepath.Join(*dataDir, "aegislure.sqlite"+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
				fatal(fmt.Errorf("remove old sqlite file: %w", err))
			}
		}
	}
	if databasePresent {
		if err := copyFileAtomic(stagedDatabase, filepath.Join(*dataDir, "aegislure.sqlite"), 0600); err != nil {
			fatal(err)
		}
	}
	if err := config.Save(*configPath, cfg); err != nil {
		fatal(err)
	}
	fmt.Printf("restored_config=%s\nrestored_data_dir=%s\n", *configPath, *dataDir)
}

func copyFileAtomic(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	tmp := destination + ".tmp"
	output, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, destination)
}

func logsCommand(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "state and event directory")
	lines := fs.Int("lines", 100, "number of recent event lines")
	_ = fs.Parse(args)
	if *lines <= 0 || *lines > 10000 {
		fatal(errors.New("--lines must be between 1 and 10000"))
	}
	f, err := os.Open(filepath.Join(*dataDir, "events.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	buffer := make([]string, 0, *lines)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		if len(buffer) == *lines {
			copy(buffer, buffer[1:])
			buffer[len(buffer)-1] = scanner.Text()
		} else {
			buffer = append(buffer, scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		fatal(err)
	}
	for _, line := range buffer {
		fmt.Println(line)
	}
}

func importCommand(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	configPath := fs.String("config", "./config.json", "runtime config path")
	input := fs.String("input", "", "third-party JSONL file")
	sourceID := fs.String("source-id", "promptpot", "stable local import source identifier")
	fileID := fs.String("file-id", "", "stable file identity; defaults to the input basename")
	product := fs.String("product", "", "source product profile")
	schemaVersion := fs.String("schema-version", "promptpot-jsonl-v1", "source schema version")
	_ = fs.Parse(args)
	if strings.TrimSpace(*input) == "" || strings.TrimSpace(*product) == "" {
		fatal(errors.New("import requires --input and --product"))
	}
	if !knownProfile(*product) {
		fatal(fmt.Errorf("unsupported import product %q", *product))
	}
	file, err := os.Open(*input)
	if err != nil {
		fatal(err)
	}
	defer file.Close()
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	st, err := store.OpenWithOptions(cfg.DataDir, cfg.InstanceKey, storeOptions(cfg))
	if err != nil {
		fatal(err)
	}
	defer st.Close()
	if source, exists := st.GetImportSource(*sourceID); exists {
		if err := validateRegisteredImportSource(source, *product, *schemaVersion); err != nil {
			fatal(fmt.Errorf("import source %q: %w", *sourceID, err))
		}
	}
	identity := *fileID
	if strings.TrimSpace(identity) == "" {
		identity = filepath.Base(*input)
	}
	stats, err := importer.ImportJSONL(file, importer.Source{ID: *sourceID, FileID: identity, Product: *product, SchemaVersion: *schemaVersion}, st)
	if err != nil {
		fatal(err)
	}
	if _, exists := st.GetImportSource(*sourceID); exists {
		if err := st.RecordImportSourceStats(*sourceID, stats.Read, stats.Imported, stats.Duplicates, stats.Rejected); err != nil {
			fatal(err)
		}
	}
	if err := st.AppendAudit(model.AuditEntry{Actor: "local_cli", Action: "import.run", Target: *sourceID, Result: "success", Metadata: map[string]string{"product": *product, "file_id_fp": security.Fingerprint(cfg.InstanceKey, identity)[:20], "imported": fmt.Sprintf("%d", stats.Imported), "duplicates": fmt.Sprintf("%d", stats.Duplicates), "rejected": fmt.Sprintf("%d", stats.Rejected)}}); err != nil {
		fatal(err)
	}
	printJSON(stats)
}

func addFile(zw *zip.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < 0 || info.Size() > 64*1024*1024 {
		return errors.New("backup input file exceeds the 64 MiB limit")
	}
	name := filepath.ToSlash(filepath.Base(path))
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, io.LimitReader(f, info.Size()))
	return err
}

func sameFilePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(filepath.Clean(left))
	rightAbs, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr != nil || rightErr != nil {
		return false
	}
	if leftAbs == rightAbs {
		return true
	}
	leftInfo, leftStatErr := os.Stat(leftAbs)
	rightInfo, rightStatErr := os.Stat(rightAbs)
	return leftStatErr == nil && rightStatErr == nil && os.SameFile(leftInfo, rightInfo)
}

func portsCommand(args []string) {
	if len(args) == 0 {
		usage()
		return
	}
	switch args[0] {
	case "plan":
		portsPlanCommand(args[1:])
	case "apply":
		portsApplyCommand(args[1:])
	default:
		usage()
	}
}

type portChangePlan struct {
	SchemaVersion int       `json:"schema_version"`
	InstanceID    string    `json:"instance_id"`
	Profile       string    `json:"profile,omitempty"`
	CurrentPort   int       `json:"current_port,omitempty"`
	DesiredPort   int       `json:"desired_port,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Signature     string    `json:"signature"`
}

func portsPlanCommand(args []string) {
	fs := flag.NewFlagSet("ports plan", flag.ExitOnError)
	configPath := fs.String("config", "./config.json", "runtime config path")
	profile := fs.String("profile", "", "profile to move")
	port := fs.Int("port", 0, "new host port")
	output := fs.String("output", "", "plan file path")
	_ = fs.Parse(args)
	cfg := loadConfig(fs)
	if *profile == "" && *port == 0 {
		printJSON(map[string]any{"admin_port": cfg.AdminPort, "profile_ports": cfg.ProfilePorts, "enabled_profiles": cfg.EnabledProfiles, "note": "Use --profile and --port to create a signed declarative plan; applying it updates only the profile mapping and requires an explicit service restart."})
		return
	}
	if *profile == "" || !knownProfile(*profile) || *port < 1 || *port > 65535 {
		fatal(errors.New("ports plan requires a known --profile and a --port between 1 and 65535"))
	}
	if !portAvailable(cfg, *profile, *port) {
		fatal(errors.New("requested port conflicts with the admin port or another profile"))
	}
	plan := portChangePlan{SchemaVersion: 1, InstanceID: cfg.InstanceID, Profile: *profile, CurrentPort: cfg.ProfilePorts[*profile], DesiredPort: *port, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(30 * time.Minute)}
	plan.Signature = signPortPlan(cfg, plan)
	path := *output
	if path == "" {
		path = filepath.Join(filepath.Dir(*configPath), "port-plan-"+security.MustRandomToken(8)+".json")
	}
	b, _ := json.MarshalIndent(plan, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
		fatal(err)
	}
	printJSON(map[string]any{"plan": path, "profile": plan.Profile, "current_port": plan.CurrentPort, "desired_port": plan.DesiredPort, "expires_at": plan.ExpiresAt, "restart_required": true})
}

func portsApplyCommand(args []string) {
	fs := flag.NewFlagSet("ports apply", flag.ExitOnError)
	input := fs.String("input", "", "signed port plan")
	configPath := fs.String("config", "./config.json", "runtime config path")
	projectDir := fs.String("project-dir", "", "project directory whose .env should be updated")
	_ = fs.Parse(args)
	if strings.TrimSpace(*input) == "" {
		fatal(errors.New("ports apply requires --input"))
	}
	cfg := loadConfig(fs)
	b, err := os.ReadFile(*input)
	if err != nil {
		fatal(err)
	}
	var plan portChangePlan
	if json.Unmarshal(b, &plan) != nil || plan.SchemaVersion != 1 || plan.InstanceID != cfg.InstanceID || plan.Profile == "" || !knownProfile(plan.Profile) || plan.DesiredPort < 1 || plan.DesiredPort > 65535 || time.Now().UTC().After(plan.ExpiresAt) || plan.Signature != signPortPlan(cfg, portChangePlan{SchemaVersion: plan.SchemaVersion, InstanceID: plan.InstanceID, Profile: plan.Profile, CurrentPort: plan.CurrentPort, DesiredPort: plan.DesiredPort, CreatedAt: plan.CreatedAt, ExpiresAt: plan.ExpiresAt}) {
		fatal(errors.New("invalid, expired, or unsigned port plan"))
	}
	if cfg.ProfilePorts[plan.Profile] != plan.CurrentPort || !portAvailable(cfg, plan.Profile, plan.DesiredPort) {
		fatal(errors.New("port plan is stale or conflicts with current configuration"))
	}
	if cfg.ProfilePorts == nil {
		cfg.ProfilePorts = make(map[string]int)
	}
	cfg.ProfilePorts[plan.Profile] = plan.DesiredPort
	if *projectDir == "" {
		*projectDir = filepath.Dir(filepath.Dir(*configPath))
		if filepath.Base(filepath.Dir(*configPath)) != "runtime" {
			*projectDir = filepath.Dir(*configPath)
		}
	}
	key := map[string]string{"new-api": "NEW_API", "vllm": "VLLM", "ollama": "OLLAMA", "sglang": "SGLANG", "localai": "LOCALAI"}[plan.Profile]
	envPath := filepath.Join(*projectDir, ".env")
	previousEnv, envExisted, err := readOptionalFile(envPath)
	if err != nil {
		fatal(fmt.Errorf("read Compose environment: %w", err))
	}
	if err := updateEnvPort(*projectDir, key, plan.DesiredPort); err != nil {
		fatal(err)
	}
	if err := config.Save(*configPath, cfg); err != nil {
		if restoreErr := restoreOptionalFile(envPath, previousEnv, envExisted); restoreErr != nil {
			fatal(fmt.Errorf("save config: %v; restore Compose environment: %w", err, restoreErr))
		}
		fatal(err)
	}
	if err := appendCLIAudit(cfg, "instance.move_port.plan_apply", "inst_"+plan.Profile, "success", map[string]string{"from_port": fmt.Sprintf("%d", plan.CurrentPort), "to_port": fmt.Sprintf("%d", plan.DesiredPort), "plan_expires_at": plan.ExpiresAt.UTC().Format(time.RFC3339)}); err != nil {
		fatal(err)
	}
	fmt.Printf("applied_profile=%s\nport=%d\nrestart_required=true\n", plan.Profile, plan.DesiredPort)
}

func updateEnvPort(projectDir, key string, port int) error {
	if key == "" || port < 1 || port > 65535 {
		return errors.New("invalid Compose port mapping")
	}
	path := filepath.Join(projectDir, ".env")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		data = nil
	} else if err != nil {
		return err
	}
	values := strings.Split(string(data), "\n")
	updates := map[string]string{key + "_PORT": fmt.Sprintf("%d", port), key + "_TARGET_PORT": fmt.Sprintf("%d", port)}
	if base, ok := composePortPoolBase(key); ok && port > base && port-base < 8 {
		// Compose exposes the base listener plus seven fixed target-port
		// candidates. A candidate move must select its published slot instead of
		// rewriting the base mapping, otherwise both entries publish the same
		// host port and Docker rejects the project.
		updates = map[string]string{fmt.Sprintf("%s_PORT_%d", key, port-base): fmt.Sprintf("%d", port)}
	}
	seen := make(map[string]bool)
	for i, line := range values {
		for name, value := range updates {
			if strings.HasPrefix(line, name+"=") {
				values[i] = name + "=" + value
				seen[name] = true
			}
		}
	}
	for name, value := range updates {
		if !seen[name] {
			values = append(values, name+"="+value)
		}
	}
	updated := strings.TrimRight(strings.Join(values, "\n"), "\n") + "\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(updated), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func composePortPoolBase(key string) (int, bool) {
	switch key {
	case "NEW_API":
		return 3000, true
	case "VLLM":
		return 8000, true
	case "OLLAMA":
		return 11434, true
	case "SGLANG":
		return 30000, true
	case "LOCALAI":
		return 8080, true
	default:
		return 0, false
	}
}

func validateRegisteredImportSource(source model.ImportSource, product, schemaVersion string) error {
	if source.Product != product || source.SchemaVersion != schemaVersion {
		return fmt.Errorf("registered for product %q and schema %q", source.Product, source.SchemaVersion)
	}
	if !source.Enabled || source.Lifecycle != "Enabled" {
		return errors.New("is not enabled")
	}
	return nil
}

func readOptionalFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func restoreOptionalFile(path string, data []byte, existed bool) error {
	if !existed {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	tmp := path + ".restore.tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func signPortPlan(cfg *config.Config, plan portChangePlan) string {
	plan.Signature = ""
	b, _ := json.Marshal(plan)
	return config.KeyedHash(cfg.InstanceKey, string(b))
}

func knownProfile(name string) bool {
	switch name {
	case "new-api", "vllm", "ollama", "sglang", "localai":
		return true
	default:
		return false
	}
}

func portAvailable(cfg *config.Config, profile string, port int) bool {
	if port == cfg.AdminPort {
		return false
	}
	for name, current := range cfg.ProfilePorts {
		if name != profile && current == port {
			return false
		}
	}
	if current, ok := cfg.ProfilePorts[profile]; ok && current == port {
		return true
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

func printJSON(value any) {
	b, _ := json.MarshalIndent(value, "", "  ")
	fmt.Println(string(b))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "hpctl:", err)
	os.Exit(1)
}

var _ = strings.TrimSpace
