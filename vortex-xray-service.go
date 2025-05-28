// services/xray/main.go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "sync"
    "syscall"
    "time"

    "github.com/fsnotify/fsnotify"
    "github.com/gofiber/fiber/v2"
    "github.com/google/uuid"
    "github.com/rabbitmq/amqp091-go"
    "github.com/redis/go-redis/v9"
    "github.com/vortexpanel/shared/models"
    "github.com/vortexpanel/shared/xray"
    "gorm.io/gorm"
)

// XrayManager manages Xray instances
type XrayManager struct {
    mu            sync.RWMutex
    instances     map[string]*XrayInstance
    db            *gorm.DB
    redis         *redis.Client
    rabbit        *amqp091.Connection
    configPath    string
    logPath       string
    statsAPI      *xray.StatsAPI
    configWatcher *fsnotify.Watcher
}

// XrayInstance represents a running Xray instance
type XrayInstance struct {
    ID          string
    Process     *os.Process
    Config      *xray.Config
    Status      InstanceStatus
    StartTime   time.Time
    RestartCount int
    mu          sync.RWMutex
}

type InstanceStatus string

const (
    StatusRunning   InstanceStatus = "running"
    StatusStopped   InstanceStatus = "stopped"
    StatusRestarting InstanceStatus = "restarting"
    StatusError     InstanceStatus = "error"
)

// NewXrayManager creates a new Xray manager
func NewXrayManager(db *gorm.DB, redis *redis.Client, rabbit *amqp091.Connection, configPath, logPath string) (*XrayManager, error) {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return nil, fmt.Errorf("failed to create watcher: %w", err)
    }

    statsAPI, err := xray.NewStatsAPI("127.0.0.1:62789")
    if err != nil {
        return nil, fmt.Errorf("failed to create stats API: %w", err)
    }

    manager := &XrayManager{
        instances:     make(map[string]*XrayInstance),
        db:            db,
        redis:         redis,
        rabbit:        rabbit,
        configPath:    configPath,
        logPath:       logPath,
        statsAPI:      statsAPI,
        configWatcher: watcher,
    }

    // Start config watcher
    go manager.watchConfig()

    return manager, nil
}

// GenerateConfig generates Xray configuration
func (m *XrayManager) GenerateConfig(ctx context.Context) (*xray.Config, error) {
    config := &xray.Config{
        Log: &xray.LogConfig{
            Access:   filepath.Join(m.logPath, "access.log"),
            Error:    filepath.Join(m.logPath, "error.log"),
            Loglevel: "warning",
        },
        API: &xray.APIConfig{
            Tag: "api",
            Services: []string{
                "HandlerService",
                "LoggerService",
                "StatsService",
            },
        },
        Stats: &xray.StatsConfig{},
        Policy: &xray.PolicyConfig{
            System: &xray.SystemPolicy{
                StatsInboundUplink:   true,
                StatsInboundDownlink: true,
                StatsOutboundUplink:  true,
                StatsOutboundDownlink: true,
            },
            Levels: map[uint32]*xray.Policy{
                0: {
                    Handshake:    4,
                    ConnIdle:     300,
                    UplinkOnly:   2,
                    DownlinkOnly: 5,
                    StatsUserUplink:   true,
                    StatsUserDownlink: true,
                    BufferSize:   10240,
                },
            },
        },
        Inbounds:  []xray.InboundConfig{},
        Outbounds: m.getDefaultOutbounds(),
        Routing:   m.getDefaultRouting(),
        DNS:       m.getDefaultDNS(),
    }

    // Add API inbound
    config.Inbounds = append(config.Inbounds, xray.InboundConfig{
        Tag:      "api",
        Port:     62789,
        Listen:   "127.0.0.1",
        Protocol: "dokodemo-door",
        Settings: json.RawMessage(`{"address": "127.0.0.1"}`),
    })

    // Add metrics inbound
    config.Inbounds = append(config.Inbounds, xray.InboundConfig{
        Tag:      "metrics",
        Port:     62788,
        Listen:   "127.0.0.1",
        Protocol: "metrics",
        Settings: json.RawMessage(`{}`),
    })

    // Get all enabled inbounds from database
    var inbounds []models.Inbound
    if err := m.db.Where("enable = ?", true).Preload("Clients").Find(&inbounds).Error; err != nil {
        return nil, fmt.Errorf("failed to get inbounds: %w", err)
    }

    // Add user inbounds
    for _, inbound := range inbounds {
        inboundConfig := xray.InboundConfig{
            Tag:            inbound.Tag,
            Port:           inbound.Port,
            Listen:         inbound.Listen,
            Protocol:       string(inbound.Protocol),
            Settings:       inbound.Settings,
            StreamSettings: inbound.StreamSettings,
            Sniffing:       inbound.Sniffing,
        }

        // Add client tags for traffic stats
        var clientTags []string
        for _, client := range inbound.Clients {
            if client.Enable {
                clientTags = append(clientTags, fmt.Sprintf("user_%s", client.ID))
            }
        }

        // Update settings with client tags
        if len(clientTags) > 0 {
            settingsMap := make(map[string]interface{})
            json.Unmarshal(inboundConfig.Settings, &settingsMap)
            settingsMap["tag"] = clientTags
            inboundConfig.Settings, _ = json.Marshal(settingsMap)
        }

        config.Inbounds = append(config.Inbounds, inboundConfig)
    }

    return config, nil
}

// Start starts a new Xray instance
func (m *XrayManager) Start(ctx context.Context, instanceID string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    // Check if instance already exists
    if instance, exists := m.instances[instanceID]; exists && instance.Status == StatusRunning {
        return fmt.Errorf("instance %s is already running", instanceID)
    }

    // Generate config
    config, err := m.GenerateConfig(ctx)
    if err != nil {
        return fmt.Errorf("failed to generate config: %w", err)
    }

    // Save config to file
    configFile := filepath.Join(m.configPath, fmt.Sprintf("config_%s.json", instanceID))
    if err := m.saveConfig(config, configFile); err != nil {
        return fmt.Errorf("failed to save config: %w", err)
    }

    // Start Xray process
    cmd := exec.Command("xray", "run", "-config", configFile)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    if err := cmd.Start(); err != nil {
        return fmt.Errorf("failed to start xray: %w", err)
    }

    instance := &XrayInstance{
        ID:        instanceID,
        Process:   cmd.Process,
        Config:    config,
        Status:    StatusRunning,
        StartTime: time.Now(),
    }

    m.instances[instanceID] = instance

    // Monitor process
    go m.monitorInstance(instance)

    // Publish event
    m.publishEvent("instance.started", map[string]interface{}{
        "instance_id": instanceID,
        "timestamp":   time.Now(),
    })

    log.Printf("Started Xray instance: %s", instanceID)

    return nil
}

// Stop stops an Xray instance
func (m *XrayManager) Stop(ctx context.Context, instanceID string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    instance, exists := m.instances[instanceID]
    if !exists {
        return fmt.Errorf("instance %s not found", instanceID)
    }

    instance.mu.Lock()
    defer instance.mu.Unlock()

    if instance.Status != StatusRunning {
        return fmt.Errorf("instance %s is not running", instanceID)
    }

    instance.Status = StatusStopped

    // Graceful shutdown
    if err := instance.Process.Signal(syscall.SIGTERM); err != nil {
        // Force kill if graceful shutdown fails
        if err := instance.Process.Kill(); err != nil {
            return fmt.Errorf("failed to kill process: %w", err)
        }
    }

    // Wait for process to exit
    _, err := instance.Process.Wait()
    if err != nil && err.Error() != "waitid: no child processes" {
        log.Printf("Error waiting for process: %v", err)
    }

    // Clean up config file
    configFile := filepath.Join(m.configPath, fmt.Sprintf("config_%s.json", instanceID))
    os.Remove(configFile)

    delete(m.instances, instanceID)

    // Publish event
    m.publishEvent("instance.stopped", map[string]interface{}{
        "instance_id": instanceID,
        "timestamp":   time.Now(),
    })

    log.Printf("Stopped Xray instance: %s", instanceID)

    return nil
}

// Restart restarts an Xray instance
func (m *XrayManager) Restart(ctx context.Context, instanceID string) error {
    log.Printf("Restarting Xray instance: %s", instanceID)

    // Stop instance
    if err := m.Stop(ctx, instanceID); err != nil {
        log.Printf("Error stopping instance during restart: %v", err)
    }

    // Wait a moment
    time.Sleep(2 * time.Second)

    // Start instance
    if err := m.Start(ctx, instanceID); err != nil {
        return fmt.Errorf("failed to start instance after restart: %w", err)
    }

    // Update restart count
    if instance, exists := m.instances[instanceID]; exists {
        instance.RestartCount++
    }

    return nil
}

// GetStats gets traffic statistics
func (m *XrayManager) GetStats(ctx context.Context, tag string, reset bool) (*xray.Stats, error) {
    stats, err := m.statsAPI.GetStats(tag, reset)
    if err != nil {
        return nil, fmt.Errorf("failed to get stats: %w", err)
    }

    // Store stats in time series database
    m.storeStats(stats)

    return stats, nil
}

// GetAllStats gets all traffic statistics
func (m *XrayManager) GetAllStats(ctx context.Context, reset bool) (map[string]*xray.Stats, error) {
    allStats := make(map[string]*xray.Stats)

    // Get all client tags
    var clients []models.Client
    if err := m.db.Where("enable = ?", true).Find(&clients).Error; err != nil {
        return nil, fmt.Errorf("failed to get clients: %w", err)
    }

    for _, client := range clients {
        tag := fmt.Sprintf("user_%s", client.ID)
        stats, err := m.statsAPI.GetStats(tag, reset)
        if err != nil {
            log.Printf("Failed to get stats for %s: %v", tag, err)
            continue
        }

        allStats[tag] = stats

        // Update client traffic in database
        client.TrafficStats = append(client.TrafficStats, models.TrafficStat{
            ID:         uuid.New(),
            ClientID:   client.ID,
            Download:   stats.Downlink,
            Upload:     stats.Uplink,
            Total:      stats.Downlink + stats.Uplink,
            RecordedAt: time.Now(),
        })

        m.db.Save(&client)
    }

    return allStats, nil
}

// monitorInstance monitors an Xray instance
func (m *XrayManager) monitorInstance(instance *XrayInstance) {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            instance.mu.RLock()
            status := instance.Status
            instance.mu.RUnlock()

            if status != StatusRunning {
                return
            }

            // Check if process is still running
            if err := instance.Process.Signal(syscall.Signal(0)); err != nil {
                log.Printf("Instance %s crashed, attempting restart", instance.ID)

                instance.mu.Lock()
                instance.Status = StatusError
                instance.mu.Unlock()

                // Attempt restart
                if instance.RestartCount < 5 {
                    time.Sleep(time.Duration(instance.RestartCount) * time.Second)
                    if err := m.Restart(context.Background(), instance.ID); err != nil {
                        log.Printf("Failed to restart instance %s: %v", instance.ID, err)
                    }
                } else {
                    log.Printf("Instance %s exceeded restart limit", instance.ID)
                    m.publishEvent("instance.failed", map[string]interface{}{
                        "instance_id": instance.ID,
                        "error":       "exceeded restart limit",
                    })
                }
                return
            }
        }
    }
}

// watchConfig watches for configuration changes
func (m *XrayManager) watchConfig() {
    for {
        select {
        case event, ok := <-m.configWatcher.Events:
            if !ok {
                return
            }

            if event.Op&fsnotify.Write == fsnotify.Write {
                log.Printf("Config file changed: %s", event.Name)
                // Trigger reload for affected instance
                m.handleConfigChange(event.Name)
            }

        case err, ok := <-m.configWatcher.Errors:
            if !ok {
                return
            }
            log.Printf("Config watcher error: %v", err)
        }
    }
}

// handleConfigChange handles configuration file changes
func (m *XrayManager) handleConfigChange(filename string) {
    // Extract instance ID from filename
    for instanceID, instance := range m.instances {
        configFile := filepath.Join(m.configPath, fmt.Sprintf("config_%s.json", instanceID))
        if configFile == filename {
            log.Printf("Reloading config for instance: %s", instanceID)
            
            // Send reload signal to Xray
            if err := instance.Process.Signal(syscall.SIGUSR1); err != nil {
                log.Printf("Failed to reload config: %v", err)
                // Fallback to restart
                m.Restart(context.Background(), instanceID)
            }
            break
        }
    }
}

// storeStats stores statistics in time series database
func (m *XrayManager) storeStats(stats *xray.Stats) {
    ctx := context.Background()

    // Store in Redis for real-time access
    key := fmt.Sprintf("stats:%s:%d", stats.Tag, time.Now().Unix())
    data, _ := json.Marshal(stats)
    m.redis.Set(ctx, key, data, 24*time.Hour)

    // Publish to analytics service via RabbitMQ
    m.publishEvent("stats.update", map[string]interface{}{
        "tag":      stats.Tag,
        "uplink":   stats.Uplink,
        "downlink": stats.Downlink,
        "timestamp": time.Now(),
    })
}

// publishEvent publishes an event to RabbitMQ
func (m *XrayManager) publishEvent(eventType string, data interface{}) {
    ch, err := m.rabbit.Channel()
    if err != nil {
        log.Printf("Failed to open channel: %v", err)
        return
    }
    defer ch.Close()

    body, _ := json.Marshal(map[string]interface{}{
        "type":      eventType,
        "data":      data,
        "timestamp": time.Now(),
    })

    err = ch.Publish(
        "vortex.events", // exchange
        eventType,       // routing key
        false,           // mandatory
        false,           // immediate
        amqp091.Publishing{
            ContentType: "application/json",
            Body:        body,
        },
    )

    if err != nil {
        log.Printf("Failed to publish event: %v", err)
    }
}

// API Handlers
func (m *XrayManager) HandleStart(c *fiber.Ctx) error {
    var req struct {
        InstanceID string `json:"instance_id"`
    }

    if err := c.BodyParser(&req); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request")
    }

    if req.InstanceID == "" {
        req.InstanceID = "main"
    }

    if err := m.Start(c.Context(), req.InstanceID); err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.JSON(fiber.Map{
        "message": "Instance started successfully",
        "instance_id": req.InstanceID,
    })
}

func (m *XrayManager) HandleStop(c *fiber.Ctx) error {
    instanceID := c.Params("id", "main")

    if err := m.Stop(c.Context(), instanceID); err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.JSON(fiber.Map{
        "message": "Instance stopped successfully",
    })
}

func (m *XrayManager) HandleRestart(c *fiber.Ctx) error {
    instanceID := c.Params("id", "main")

    if err := m.Restart(c.Context(), instanceID); err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.JSON(fiber.Map{
        "message": "Instance restarted successfully",
    })
}

func (m *XrayManager) HandleGetStatus(c *fiber.Ctx) error {
    status := make(map[string]interface{})

    m.mu.RLock()
    for id, instance := range m.instances {
        instance.mu.RLock()
        status[id] = map[string]interface{}{
            "status":        instance.Status,
            "start_time":    instance.StartTime,
            "restart_count": instance.RestartCount,
            "uptime":        time.Since(instance.StartTime).Seconds(),
        }
        instance.mu.RUnlock()
    }
    m.mu.RUnlock()

    return c.JSON(status)
}

func (m *XrayManager) HandleGetStats(c *fiber.Ctx) error {
    tag := c.Query("tag")
    reset := c.QueryBool("reset", false)

    if tag != "" {
        stats, err := m.GetStats(c.Context(), tag, reset)
        if err != nil {
            return fiber.NewError(fiber.StatusInternalServerError, err.Error())
        }
        return c.JSON(stats)
    }

    // Get all stats
    allStats, err := m.GetAllStats(c.Context(), reset)
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.JSON(allStats)
}

func (m *XrayManager) HandleUpdateConfig(c *fiber.Ctx) error {
    var config xray.Config
    if err := c.BodyParser(&config); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid config")
    }

    // Validate config
    if err := config.Validate(); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, err.Error())
    }

    // Save config
    instanceID := c.Query("instance_id", "main")
    configFile := filepath.Join(m.configPath, fmt.Sprintf("config_%s.json", instanceID))
    
    if err := m.saveConfig(&config, configFile); err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    // Reload or restart instance
    if instance, exists := m.instances[instanceID]; exists && instance.Status == StatusRunning {
        // Try hot reload first
        if err := instance.Process.Signal(syscall.SIGUSR1); err != nil {
            // Fallback to restart
            if err := m.Restart(c.Context(), instanceID); err != nil {
                return fiber.NewError(fiber.StatusInternalServerError, err.Error())
            }
        }
    }

    return c.JSON(fiber.Map{
        "message": "Config updated successfully",
    })
}

// Helper methods
func (m *XrayManager) saveConfig(config *xray.Config, filename string) error {
    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal config: %w", err)
    }

    if err := os.WriteFile(filename, data, 0644); err != nil {
        return fmt.Errorf("failed to write config: %w", err)
    }

    // Add to watcher
    m.configWatcher.Add(filename)

    return nil
}

func (m *XrayManager) getDefaultOutbounds() []xray.OutboundConfig {
    return []xray.OutboundConfig{
        {
            Tag:      "direct",
            Protocol: "freedom",
            Settings: json.RawMessage(`{}`),
        },
        {
            Tag:      "blocked",
            Protocol: "blackhole",
            Settings: json.RawMessage(`{"response": {"type": "http"}}`),
        },
        {
            Tag:      "warp",
            Protocol: "socks",
            Settings: json.RawMessage(`{
                "servers": [{
                    "address": "127.0.0.1",
                    "port": 40000
                }]
            }`),
        },
    }
}

func (m *XrayManager) getDefaultRouting() *xray.RoutingConfig {
    return &xray.RoutingConfig{
        DomainStrategy: "AsIs",
        Rules: []xray.RoutingRule{
            {
                Type:        "field",
                InboundTag:  []string{"api"},
                OutboundTag: "api",
            },
            {
                Type:        "field",
                Protocol:    []string{"bittorrent"},
                OutboundTag: "blocked",
            },
            {
                Type:        "field",
                IP:          []string{"geoip:private"},
                OutboundTag: "blocked",
            },
            {
                Type:        "field",
                Domain:      []string{"geosite:category-ads-all"},
                OutboundTag: "blocked",
            },
        ],
    }
}

func (m *XrayManager) getDefaultDNS() *xray.DNSConfig {
    return &xray.DNSConfig{
        Servers: []interface{}{
            "1.1.1.1",
            "8.8.8.8",
            map[string]interface{}{
                "address": "114.114.114.114",
                "domains": []string{"geosite:cn"},
            },
        },
    }
}

// Main function
func main() {
    // Load config
    config := loadConfig()

    // Connect to database
    db, err := connectDB(config.Database.URL)
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }

    // Connect to Redis
    redis := redis.NewClient(&redis.Options{
        Addr:     config.Redis.Addr,
        Password: config.Redis.Password,
        DB:       config.Redis.DB,
    })

    // Connect to RabbitMQ
    rabbit, err := amqp091.Dial(config.RabbitMQ.URL)
    if err != nil {
        log.Fatal("Failed to connect to RabbitMQ:", err)
    }
    defer rabbit.Close()

    // Create Xray manager
    manager, err := NewXrayManager(db, redis, rabbit, config.Xray.ConfigPath, config.Xray.LogPath)
    if err != nil {
        log.Fatal("Failed to create Xray manager:", err)
    }

    // Create fiber app
    app := fiber.New(fiber.Config{
        AppName: "VortexPanel Xray Service",
    })

    // Routes
    api := app.Group("/api/v1")
    
    api.Post("/instances/start", manager.HandleStart)
    api.Post("/instances/:id/stop", manager.HandleStop)
    api.Post("/instances/:id/restart", manager.HandleRestart)
    api.Get("/instances/status", manager.HandleGetStatus)
    api.Get("/stats", manager.HandleGetStats)
    api.Put("/config", manager.HandleUpdateConfig)

    // Health check
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"status": "ok"})
    })

    // Start default instance
    go func() {
        time.Sleep(5 * time.Second)
        if err := manager.Start(context.Background(), "main"); err != nil {
            log.Printf("Failed to start default instance: %v", err)
        }
    }()

    // Start server
    go func() {
        if err := app.Listen(":8082"); err != nil {
            log.Fatal("Failed to start server:", err)
        }
    }()

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Shutting down Xray service...")

    // Stop all instances
    manager.mu.Lock()
    for id := range manager.instances {
        manager.Stop(context.Background(), id)
    }
    manager.mu.Unlock()

    app.Shutdown()
    log.Println("Xray service stopped")
}