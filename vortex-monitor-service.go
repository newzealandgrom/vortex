// services/monitor/main.go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "math"
    "net/http"
    "os"
    "os/signal"
    "runtime"
    "sync"
    "syscall"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/google/uuid"
    "github.com/influxdata/influxdb-client-go/v2"
    "github.com/influxdata/influxdb-client-go/v2/api"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/redis/go-redis/v9"
    "github.com/shirou/gopsutil/v3/cpu"
    "github.com/shirou/gopsutil/v3/disk"
    "github.com/shirou/gopsutil/v3/host"
    "github.com/shirou/gopsutil/v3/mem"
    "github.com/shirou/gopsutil/v3/net"
    "github.com/vortexpanel/shared/models"
    "gorm.io/gorm"
)

// MonitorService handles system monitoring
type MonitorService struct {
    db              *gorm.DB
    redis           *redis.Client
    influx          influxdb2.Client
    influxAPI       api.WriteAPIBlocking
    queryAPI        api.QueryAPI
    healthChecks    map[string]*HealthCheck
    alerts          map[string]*Alert
    mu              sync.RWMutex
    metrics         *MetricsCollector
    incidentManager *IncidentManager
}

// HealthCheck represents a health check
type HealthCheck struct {
    ID              string              `json:"id"`
    Name            string              `json:"name"`
    Type            HealthCheckType     `json:"type"`
    Target          string              `json:"target"`
    Interval        time.Duration       `json:"interval"`
    Timeout         time.Duration       `json:"timeout"`
    Retries         int                 `json:"retries"`
    Status          HealthStatus        `json:"status"`
    LastCheck       time.Time           `json:"last_check"`
    LastSuccess     time.Time           `json:"last_success"`
    LastFailure     time.Time           `json:"last_failure"`
    ConsecutiveFails int                `json:"consecutive_fails"`
    Metadata        map[string]string   `json:"metadata"`
    checker         HealthChecker
    stopChan        chan struct{}
}

type HealthCheckType string

const (
    CheckTypeHTTP     HealthCheckType = "http"
    CheckTypeTCP      HealthCheckType = "tcp"
    CheckTypePing     HealthCheckType = "ping"
    CheckTypeDNS      HealthCheckType = "dns"
    CheckTypeProcess  HealthCheckType = "process"
    CheckTypeDatabase HealthCheckType = "database"
    CheckTypeRedis    HealthCheckType = "redis"
    CheckTypeXray     HealthCheckType = "xray"
)

type HealthStatus string

const (
    StatusHealthy   HealthStatus = "healthy"
    StatusDegraded  HealthStatus = "degraded"
    StatusUnhealthy HealthStatus = "unhealthy"
    StatusUnknown   HealthStatus = "unknown"
)

// Alert represents a monitoring alert
type Alert struct {
    ID          uuid.UUID          `gorm:"type:uuid;primary_key" json:"id"`
    Name        string             `gorm:"not null" json:"name"`
    Type        AlertType          `gorm:"not null" json:"type"`
    Condition   AlertCondition     `gorm:"type:jsonb;not null" json:"condition"`
    Actions     []AlertAction      `gorm:"type:jsonb" json:"actions"`
    Severity    AlertSeverity      `gorm:"not null" json:"severity"`
    Enabled     bool               `gorm:"default:true" json:"enabled"`
    LastFired   *time.Time         `json:"last_fired,omitempty"`
    FireCount   int                `gorm:"default:0" json:"fire_count"`
    Metadata    map[string]string  `gorm:"type:jsonb" json:"metadata"`
    CreatedAt   time.Time          `json:"created_at"`
    UpdatedAt   time.Time          `json:"updated_at"`
}

type AlertType string

const (
    AlertTypeThreshold   AlertType = "threshold"
    AlertTypeAnomaly     AlertType = "anomaly"
    AlertTypeHealthCheck AlertType = "health_check"
    AlertTypeCustom      AlertType = "custom"
)

type AlertCondition struct {
    Metric       string                 `json:"metric"`
    Operator     string                 `json:"operator"`
    Value        float64                `json:"value"`
    Duration     string                 `json:"duration"`
    Aggregation  string                 `json:"aggregation"`
    Filters      map[string]string      `json:"filters"`
}

type AlertAction struct {
    Type     string                 `json:"type"`
    Config   map[string]interface{} `json:"config"`
}

type AlertSeverity string

const (
    SeverityInfo     AlertSeverity = "info"
    SeverityWarning  AlertSeverity = "warning"
    SeverityCritical AlertSeverity = "critical"
)

// MetricsCollector collects system metrics
type MetricsCollector struct {
    // Prometheus metrics
    cpuUsage        prometheus.Gauge
    memoryUsage     prometheus.Gauge
    diskUsage       prometheus.Gauge
    networkRx       prometheus.Counter
    networkTx       prometheus.Counter
    activeUsers     prometheus.Gauge
    activeConns     prometheus.Gauge
    requestDuration prometheus.Histogram
    errorRate       prometheus.Counter
}

// IncidentManager manages incidents
type IncidentManager struct {
    db        *gorm.DB
    incidents map[string]*Incident
    mu        sync.RWMutex
}

type Incident struct {
    ID           uuid.UUID        `gorm:"type:uuid;primary_key" json:"id"`
    Title        string           `gorm:"not null" json:"title"`
    Description  string           `json:"description"`
    Severity     AlertSeverity    `gorm:"not null" json:"severity"`
    Status       IncidentStatus   `gorm:"not null" json:"status"`
    Source       string           `json:"source"`
    StartedAt    time.Time        `json:"started_at"`
    ResolvedAt   *time.Time       `json:"resolved_at,omitempty"`
    Timeline     []IncidentEvent  `gorm:"type:jsonb" json:"timeline"`
    AffectedUsers []uuid.UUID     `gorm:"type:uuid[]" json:"affected_users"`
    Tags         []string         `gorm:"type:text[]" json:"tags"`
    CreatedAt    time.Time        `json:"created_at"`
    UpdatedAt    time.Time        `json:"updated_at"`
}

type IncidentStatus string

const (
    IncidentOpen       IncidentStatus = "open"
    IncidentInProgress IncidentStatus = "in_progress"
    IncidentResolved   IncidentStatus = "resolved"
    IncidentClosed     IncidentStatus = "closed"
)

type IncidentEvent struct {
    Timestamp   time.Time `json:"timestamp"`
    Type        string    `json:"type"`
    Description string    `json:"description"`
    User        string    `json:"user,omitempty"`
}

// HealthChecker interface
type HealthChecker interface {
    Check(ctx context.Context) error
}

// HTTP health checker
type HTTPChecker struct {
    URL            string
    Method         string
    Headers        map[string]string
    ExpectedStatus int
    client         *http.Client
}

func (h *HTTPChecker) Check(ctx context.Context) error {
    req, err := http.NewRequestWithContext(ctx, h.Method, h.URL, nil)
    if err != nil {
        return err
    }

    for key, value := range h.Headers {
        req.Header.Set(key, value)
    }

    resp, err := h.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if h.ExpectedStatus > 0 && resp.StatusCode != h.ExpectedStatus {
        return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }

    if h.ExpectedStatus == 0 && resp.StatusCode >= 400 {
        return fmt.Errorf("error status code: %d", resp.StatusCode)
    }

    return nil
}

// NewMonitorService creates a new monitor service
func NewMonitorService(db *gorm.DB, redis *redis.Client, influxURL, influxToken, influxOrg, influxBucket string) (*MonitorService, error) {
    client := influxdb2.NewClient(influxURL, influxToken)
    writeAPI := client.WriteAPIBlocking(influxOrg, influxBucket)
    queryAPI := client.QueryAPI(influxOrg)

    // Initialize metrics collector
    metrics := &MetricsCollector{
        cpuUsage: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: "vortex_cpu_usage_percent",
            Help: "Current CPU usage percentage",
        }),
        memoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: "vortex_memory_usage_percent",
            Help: "Current memory usage percentage",
        }),
        diskUsage: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: "vortex_disk_usage_percent",
            Help: "Current disk usage percentage",
        }),
        networkRx: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "vortex_network_rx_bytes_total",
            Help: "Total received bytes",
        }),
        networkTx: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "vortex_network_tx_bytes_total",
            Help: "Total transmitted bytes",
        }),
        activeUsers: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: "vortex_active_users",
            Help: "Number of active users",
        }),
        activeConns: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: "vortex_active_connections",
            Help: "Number of active connections",
        }),
        requestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
            Name:    "vortex_request_duration_seconds",
            Help:    "Request duration in seconds",
            Buckets: prometheus.DefBuckets,
        }),
        errorRate: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "vortex_errors_total",
            Help: "Total number of errors",
        }),
    }

    // Register metrics
    prometheus.MustRegister(metrics.cpuUsage)
    prometheus.MustRegister(metrics.memoryUsage)
    prometheus.MustRegister(metrics.diskUsage)
    prometheus.MustRegister(metrics.networkRx)
    prometheus.MustRegister(metrics.networkTx)
    prometheus.MustRegister(metrics.activeUsers)
    prometheus.MustRegister(metrics.activeConns)
    prometheus.MustRegister(metrics.requestDuration)
    prometheus.MustRegister(metrics.errorRate)

    service := &MonitorService{
        db:           db,
        redis:        redis,
        influx:       client,
        influxAPI:    writeAPI,
        queryAPI:     queryAPI,
        healthChecks: make(map[string]*HealthCheck),
        alerts:       make(map[string]*Alert),
        metrics:      metrics,
        incidentManager: &IncidentManager{
            db:        db,
            incidents: make(map[string]*Incident),
        },
    }

    // Load health checks and alerts from database
    service.loadHealthChecks()
    service.loadAlerts()

    // Start monitoring loops
    go service.collectSystemMetrics()
    go service.runHealthChecks()
    go service.processAlerts()

    return service, nil
}

// collectSystemMetrics collects system metrics
func (s *MonitorService) collectSystemMetrics() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    var lastNetStats *net.IOCountersStat

    for range ticker.C {
        ctx := context.Background()

        // CPU usage
        cpuPercent, err := cpu.Percent(time.Second, false)
        if err == nil && len(cpuPercent) > 0 {
            s.metrics.cpuUsage.Set(cpuPercent[0])
            s.writeMetric(ctx, "cpu_usage", cpuPercent[0], nil)
        }

        // Memory usage
        memInfo, err := mem.VirtualMemory()
        if err == nil {
            s.metrics.memoryUsage.Set(memInfo.UsedPercent)
            s.writeMetric(ctx, "memory_usage", memInfo.UsedPercent, nil)
            s.writeMetric(ctx, "memory_used", float64(memInfo.Used), nil)
            s.writeMetric(ctx, "memory_total", float64(memInfo.Total), nil)
        }

        // Disk usage
        diskInfo, err := disk.Usage("/")
        if err == nil {
            s.metrics.diskUsage.Set(diskInfo.UsedPercent)
            s.writeMetric(ctx, "disk_usage", diskInfo.UsedPercent, nil)
            s.writeMetric(ctx, "disk_used", float64(diskInfo.Used), nil)
            s.writeMetric(ctx, "disk_total", float64(diskInfo.Total), nil)
        }

        // Network I/O
        netStats, err := net.IOCounters(false)
        if err == nil && len(netStats) > 0 {
            if lastNetStats != nil {
                rxBytes := float64(netStats[0].BytesRecv - lastNetStats.BytesRecv)
                txBytes := float64(netStats[0].BytesSent - lastNetStats.BytesSent)
                
                s.metrics.networkRx.Add(rxBytes)
                s.metrics.networkTx.Add(txBytes)
                
                s.writeMetric(ctx, "network_rx_bytes", rxBytes, nil)
                s.writeMetric(ctx, "network_tx_bytes", txBytes, nil)
            }
            lastNetStats = &netStats[0]
        }

        // Active users and connections
        var activeUsers int64
        s.db.Model(&models.Client{}).Where("enable = ? AND (expiry_time IS NULL OR expiry_time > ?)", true, time.Now()).Count(&activeUsers)
        s.metrics.activeUsers.Set(float64(activeUsers))
        s.writeMetric(ctx, "active_users", float64(activeUsers), nil)

        // Get active connections from Redis
        activeConns, _ := s.redis.SCard(ctx, "active:connections").Result()
        s.metrics.activeConns.Set(float64(activeConns))
        s.writeMetric(ctx, "active_connections", float64(activeConns), nil)

        // Go runtime metrics
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        s.writeMetric(ctx, "go_goroutines", float64(runtime.NumGoroutine()), nil)
        s.writeMetric(ctx, "go_memory_alloc", float64(m.Alloc), nil)
        s.writeMetric(ctx, "go_memory_sys", float64(m.Sys), nil)
        s.writeMetric(ctx, "go_gc_runs", float64(m.NumGC), nil)
    }
}

// runHealthChecks runs all health checks
func (s *MonitorService) runHealthChecks() {
    s.mu.RLock()
    for _, check := range s.healthChecks {
        go s.runHealthCheck(check)
    }
    s.mu.RUnlock()
}

// runHealthCheck runs a single health check
func (s *MonitorService) runHealthCheck(check *HealthCheck) {
    ticker := time.NewTicker(check.Interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            s.performHealthCheck(check)
        case <-check.stopChan:
            return
        }
    }
}

// performHealthCheck performs a health check
func (s *MonitorService) performHealthCheck(check *HealthCheck) {
    ctx, cancel := context.WithTimeout(context.Background(), check.Timeout)
    defer cancel()

    startTime := time.Now()
    err := check.checker.Check(ctx)
    duration := time.Since(startTime)

    check.LastCheck = time.Now()

    if err != nil {
        check.ConsecutiveFails++
        check.LastFailure = time.Now()
        
        if check.ConsecutiveFails >= check.Retries {
            oldStatus := check.Status
            check.Status = StatusUnhealthy
            
            if oldStatus != StatusUnhealthy {
                // Status changed to unhealthy
                s.handleHealthCheckFailure(check, err)
            }
        }
        
        log.Printf("Health check %s failed: %v", check.Name, err)
    } else {
        oldStatus := check.Status
        check.ConsecutiveFails = 0
        check.LastSuccess = time.Now()
        check.Status = StatusHealthy
        
        if oldStatus != StatusHealthy {
            // Status changed to healthy
            s.handleHealthCheckRecovery(check)
        }
    }

    // Write metrics
    s.writeMetric(context.Background(), "health_check_duration", duration.Seconds(), map[string]string{
        "check_name": check.Name,
        "check_type": string(check.Type),
        "status":     string(check.Status),
    })

    s.writeMetric(context.Background(), "health_check_status", float64(s.statusToInt(check.Status)), map[string]string{
        "check_name": check.Name,
        "check_type": string(check.Type),
    })
}

// processAlerts processes alerts
func (s *MonitorService) processAlerts() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        s.mu.RLock()
        alerts := make([]*Alert, 0, len(s.alerts))
        for _, alert := range s.alerts {
            if alert.Enabled {
                alerts = append(alerts, alert)
            }
        }
        s.mu.RUnlock()

        for _, alert := range alerts {
            s.evaluateAlert(alert)
        }
    }
}

// evaluateAlert evaluates an alert condition
func (s *MonitorService) evaluateAlert(alert *Alert) {
    ctx := context.Background()

    switch alert.Type {
    case AlertTypeThreshold:
        s.evaluateThresholdAlert(ctx, alert)
    case AlertTypeAnomaly:
        s.evaluateAnomalyAlert(ctx, alert)
    case AlertTypeHealthCheck:
        s.evaluateHealthCheckAlert(ctx, alert)
    }
}

// evaluateThresholdAlert evaluates a threshold alert
func (s *MonitorService) evaluateThresholdAlert(ctx context.Context, alert *Alert) {
    // Query metric value
    query := fmt.Sprintf(`
        from(bucket: "vortex")
        |> range(start: -%s)
        |> filter(fn: (r) => r["_measurement"] == "%s")
        |> aggregateWindow(every: %s, fn: %s, createEmpty: false)
        |> last()
    `, alert.Condition.Duration, alert.Condition.Metric, 
       alert.Condition.Duration, alert.Condition.Aggregation)

    result, err := s.queryAPI.Query(ctx, query)
    if err != nil {
        log.Printf("Failed to query metric for alert %s: %v", alert.Name, err)
        return
    }

    var value float64
    var found bool

    for result.Next() {
        record := result.Record()
        if v, ok := record.Value().(float64); ok {
            value = v
            found = true
            break
        }
    }

    if !found {
        return
    }

    // Evaluate condition
    shouldFire := false
    switch alert.Condition.Operator {
    case ">":
        shouldFire = value > alert.Condition.Value
    case "<":
        shouldFire = value < alert.Condition.Value
    case ">=":
        shouldFire = value >= alert.Condition.Value
    case "<=":
        shouldFire = value <= alert.Condition.Value
    case "==":
        shouldFire = value == alert.Condition.Value
    case "!=":
        shouldFire = value != alert.Condition.Value
    }

    if shouldFire {
        s.fireAlert(alert, map[string]interface{}{
            "value":     value,
            "threshold": alert.Condition.Value,
            "metric":    alert.Condition.Metric,
        })
    }
}

// fireAlert fires an alert
func (s *MonitorService) fireAlert(alert *Alert, data map[string]interface{}) {
    // Check if alert was recently fired
    if alert.LastFired != nil && time.Since(*alert.LastFired) < 5*time.Minute {
        return
    }

    now := time.Now()
    alert.LastFired = &now
    alert.FireCount++
    s.db.Save(alert)

    // Create incident if critical
    if alert.Severity == SeverityCritical {
        incident := &Incident{
            ID:          uuid.New(),
            Title:       fmt.Sprintf("Alert: %s", alert.Name),
            Description: fmt.Sprintf("Alert %s triggered", alert.Name),
            Severity:    alert.Severity,
            Status:      IncidentOpen,
            Source:      "monitor",
            StartedAt:   now,
            Timeline: []IncidentEvent{
                {
                    Timestamp:   now,
                    Type:        "alert_fired",
                    Description: "Alert triggered",
                },
            },
        }
        s.incidentManager.CreateIncident(incident)
    }

    // Execute actions
    for _, action := range alert.Actions {
        s.executeAlertAction(alert, action, data)
    }
}

// executeAlertAction executes an alert action
func (s *MonitorService) executeAlertAction(alert *Alert, action AlertAction, data map[string]interface{}) {
    switch action.Type {
    case "notification":
        s.sendAlertNotification(alert, data)
    case "webhook":
        s.callAlertWebhook(alert, action, data)
    case "command":
        s.executeAlertCommand(alert, action, data)
    }
}

// Helper methods
func (s *MonitorService) writeMetric(ctx context.Context, measurement string, value float64, tags map[string]string) {
    point := influxdb2.NewPoint(measurement, tags, map[string]interface{}{"value": value}, time.Now())
    if err := s.influxAPI.WritePoint(ctx, point); err != nil {
        log.Printf("Failed to write metric %s: %v", measurement, err)
    }
}

func (s *MonitorService) statusToInt(status HealthStatus) int {
    switch status {
    case StatusHealthy:
        return 1
    case StatusDegraded:
        return 2
    case StatusUnhealthy:
        return 3
    default:
        return 0
    }
}

func (s *MonitorService) loadHealthChecks() {
    // Load from configuration or database
    // Example health checks
    s.AddHealthCheck(&HealthCheck{
        ID:       "api-health",
        Name:     "API Health",
        Type:     CheckTypeHTTP,
        Target:   "http://localhost:8080/health",
        Interval: 30 * time.Second,
        Timeout:  5 * time.Second,
        Retries:  3,
        checker: &HTTPChecker{
            URL:            "http://localhost:8080/health",
            Method:         "GET",
            ExpectedStatus: 200,
            client:         &http.Client{Timeout: 5 * time.Second},
        },
    })
}

func (s *MonitorService) loadAlerts() {
    var alerts []Alert
    s.db.Find(&alerts)
    
    for _, alert := range alerts {
        s.alerts[alert.ID.String()] = &alert
    }
}

// AddHealthCheck adds a health check
func (s *MonitorService) AddHealthCheck(check *HealthCheck) {
    s.mu.Lock()
    defer s.mu.Unlock()

    check.stopChan = make(chan struct{})
    check.Status = StatusUnknown
    s.healthChecks[check.ID] = check

    go s.runHealthCheck(check)
}

// RemoveHealthCheck removes a health check
func (s *MonitorService) RemoveHealthCheck(id string) {
    s.mu.Lock()
    defer s.mu.Unlock()

    if check, exists := s.healthChecks[id]; exists {
        close(check.stopChan)
        delete(s.healthChecks, id)
    }
}

// API Handlers
func (s *MonitorService) HandleGetSystemStatus(c *fiber.Ctx) error {
    ctx := c.Context()

    // Get system info
    hostInfo, _ := host.Info()
    cpuInfo, _ := cpu.Info()
    memInfo, _ := mem.VirtualMemory()
    diskInfo, _ := disk.Usage("/")

    status := fiber.Map{
        "system": fiber.Map{
            "hostname":        hostInfo.Hostname,
            "platform":        hostInfo.Platform,
            "platform_version": hostInfo.PlatformVersion,
            "uptime":          hostInfo.Uptime,
            "boot_time":       hostInfo.BootTime,
        },
        "cpu": fiber.Map{
            "model":   cpuInfo[0].ModelName,
            "cores":   runtime.NumCPU(),
            "usage":   s.getCurrentCPUUsage(),
        },
        "memory": fiber.Map{
            "total":        memInfo.Total,
            "available":    memInfo.Available,
            "used":         memInfo.Used,
            "used_percent": memInfo.UsedPercent,
        },
        "disk": fiber.Map{
            "total":        diskInfo.Total,
            "free":         diskInfo.Free,
            "used":         diskInfo.Used,
            "used_percent": diskInfo.UsedPercent,
        },
        "services": s.getServicesStatus(),
    }

    return c.JSON(status)
}

func (s *MonitorService) HandleGetHealthChecks(c *fiber.Ctx) error {
    s.mu.RLock()
    defer s.mu.RUnlock()

    checks := make([]HealthCheck, 0, len(s.healthChecks))
    for _, check := range s.healthChecks {
        checks = append(checks, *check)
    }

    return c.JSON(checks)
}

func (s *MonitorService) HandleCreateHealthCheck(c *fiber.Ctx) error {
    var check HealthCheck
    if err := c.BodyParser(&check); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request")
    }

    check.ID = uuid.New().String()
    
    // Create appropriate checker based on type
    switch check.Type {
    case CheckTypeHTTP:
        check.checker = &HTTPChecker{
            URL:            check.Target,
            Method:         "GET",
            ExpectedStatus: 200,
            client:         &http.Client{Timeout: check.Timeout},
        }
    default:
        return fiber.NewError(fiber.StatusBadRequest, "Unsupported check type")
    }

    s.AddHealthCheck(&check)

    return c.Status(fiber.StatusCreated).JSON(check)
}

func (s *MonitorService) HandleDeleteHealthCheck(c *fiber.Ctx) error {
    id := c.Params("id")
    s.RemoveHealthCheck(id)
    
    return c.JSON(fiber.Map{
        "message": "Health check deleted successfully",
    })
}

func (s *MonitorService) HandleGetAlerts(c *fiber.Ctx) error {
    var alerts []Alert
    s.db.Find(&alerts)
    return c.JSON(alerts)
}

func (s *MonitorService) HandleCreateAlert(c *fiber.Ctx) error {
    var alert Alert
    if err := c.BodyParser(&alert); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request")
    }

    alert.ID = uuid.New()
    alert.CreatedAt = time.Now()
    alert.UpdatedAt = time.Now()

    if err := s.db.Create(&alert).Error; err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    s.mu.Lock()
    s.alerts[alert.ID.String()] = &alert
    s.mu.Unlock()

    return c.Status(fiber.StatusCreated).JSON(alert)
}

func (s *MonitorService) HandleGetIncidents(c *fiber.Ctx) error {
    page := c.QueryInt("page", 1)
    limit := c.QueryInt("limit", 20)
    offset := (page - 1) * limit

    var incidents []Incident
    var total int64

    query := s.db.Model(&Incident{})
    
    // Apply filters
    if status := c.Query("status"); status != "" {
        query = query.Where("status = ?", status)
    }
    
    if severity := c.Query("severity"); severity != "" {
        query = query.Where("severity = ?", severity)
    }

    query.Count(&total)
    query.Order("created_at DESC").Offset(offset).Limit(limit).Find(&incidents)

    return c.JSON(fiber.Map{
        "incidents": incidents,
        "total":     total,
        "page":      page,
        "limit":     limit,
    })
}

func (s *MonitorService) HandleGetMetrics(c *fiber.Ctx) error {
    metric := c.Query("metric", "cpu_usage")
    period := c.Query("period", "1h")
    
    query := fmt.Sprintf(`
        from(bucket: "vortex")
        |> range(start: -%s)
        |> filter(fn: (r) => r["_measurement"] == "%s")
        |> aggregateWindow(every: 1m, fn: mean, createEmpty: false)
        |> yield(name: "mean")
    `, period, metric)

    result, err := s.queryAPI.Query(c.Context(), query)
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    data := []fiber.Map{}
    for result.Next() {
        record := result.Record()
        data = append(data, fiber.Map{
            "time":  record.Time(),
            "value": record.Value(),
        })
    }

    return c.JSON(data)
}

// Helper methods for handlers
func (s *MonitorService) getCurrentCPUUsage() float64 {
    cpuPercent, err := cpu.Percent(time.Second, false)
    if err == nil && len(cpuPercent) > 0 {
        return math.Round(cpuPercent[0]*100) / 100
    }
    return 0
}

func (s *MonitorService) getServicesStatus() map[string]interface{} {
    ctx := context.Background()
    services := make(map[string]interface{})

    // Check database
    var result int
    err := s.db.Raw("SELECT 1").Scan(&result).Error
    services["database"] = fiber.Map{
        "status": s.errorToStatus(err),
        "error":  s.errorToString(err),
    }

    // Check Redis
    _, err = s.redis.Ping(ctx).Result()
    services["redis"] = fiber.Map{
        "status": s.errorToStatus(err),
        "error":  s.errorToString(err),
    }

    // Check InfluxDB
    health, err := s.influx.Health(ctx)
    services["influxdb"] = fiber.Map{
        "status": s.healthToStatus(health),
        "error":  s.errorToString(err),
    }

    return services
}

func (s *MonitorService) errorToStatus(err error) string {
    if err == nil {
        return "healthy"
    }
    return "unhealthy"
}

func (s *MonitorService) healthToStatus(health *influxdb2.HealthCheck) string {
    if health != nil && health.Status == "pass" {
        return "healthy"
    }
    return "unhealthy"
}

func (s *MonitorService) errorToString(err error) string {
    if err != nil {
        return err.Error()
    }
    return ""
}

// IncidentManager methods
func (im *IncidentManager) CreateIncident(incident *Incident) error {
    im.mu.Lock()
    defer im.mu.Unlock()

    incident.CreatedAt = time.Now()
    incident.UpdatedAt = time.Now()

    if err := im.db.Create(incident).Error; err != nil {
        return err
    }

    im.incidents[incident.ID.String()] = incident
    return nil
}

func (im *IncidentManager) UpdateIncident(id uuid.UUID, updates map[string]interface{}) error {
    im.mu.Lock()
    defer im.mu.Unlock()

    updates["updated_at"] = time.Now()
    
    if err := im.db.Model(&Incident{}).Where("id = ?", id).Updates(updates).Error; err != nil {
        return err
    }

    if incident, exists := im.incidents[id.String()]; exists {
        // Update in-memory incident
        im.db.First(incident, id)
    }

    return nil
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

    // Auto migrate
    db.AutoMigrate(&Alert{}, &Incident{})

    // Connect to Redis
    redis := redis.NewClient(&redis.Options{
        Addr:     config.Redis.Addr,
        Password: config.Redis.Password,
        DB:       config.Redis.DB,
    })

    // Create monitor service
    service, err := NewMonitorService(
        db, 
        redis,
        config.InfluxDB.URL,
        config.InfluxDB.Token,
        config.InfluxDB.Org,
        config.InfluxDB.Bucket,
    )
    if err != nil {
        log.Fatal("Failed to create monitor service:", err)
    }

    // Create fiber app
    app := fiber.New(fiber.Config{
        AppName: "VortexPanel Monitor Service",
    })

    // Prometheus metrics endpoint
    app.Get("/metrics", func(c *fiber.Ctx) error {
        handler := promhttp.Handler()
        handler.ServeHTTP(c.Context().ResponseWriter(), c.Context().Request)
        return nil
    })

    // Routes
    api := app.Group("/api/v1")
    
    api.Get("/status", service.HandleGetSystemStatus)
    api.Get("/health-checks", service.HandleGetHealthChecks)
    api.Post("/health-checks", service.HandleCreateHealthCheck)
    api.Delete("/health-checks/:id", service.HandleDeleteHealthCheck)
    api.Get("/alerts", service.HandleGetAlerts)
    api.Post("/alerts", service.HandleCreateAlert)
    api.Get("/incidents", service.HandleGetIncidents)
    api.Get("/metrics", service.HandleGetMetrics)

    // Health check
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"status": "ok"})
    })

    // Start server
    go func() {
        if err := app.Listen(":8085"); err != nil {
            log.Fatal("Failed to start server:", err)
        }
    }()

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Shutting down monitor service...")
    app.Shutdown()
    log.Println("Monitor service stopped")
}