// services/analytics/main.go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "math"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/influxdata/influxdb-client-go/v2"
    "github.com/influxdata/influxdb-client-go/v2/api"
    "github.com/redis/go-redis/v9"
    "github.com/vortexpanel/shared/models"
    "gorm.io/gorm"
)

// AnalyticsService handles all analytics and metrics
type AnalyticsService struct {
    db           *gorm.DB
    influx       influxdb2.Client
    influxAPI    api.WriteAPIBlocking
    queryAPI     api.QueryAPI
    redis        *redis.Client
    mlPredictor  *MLPredictor
}

// MLPredictor for AI-powered predictions
type MLPredictor struct {
    model        interface{} // TensorFlow model placeholder
    trafficCache *TrafficCache
}

// TrafficCache for caching traffic patterns
type TrafficCache struct {
    patterns map[string]*TrafficPattern
}

// TrafficPattern represents traffic behavior
type TrafficPattern struct {
    UserID       string
    AvgBandwidth float64
    PeakHours    []int
    Consistency  float64
    LastUpdated  time.Time
}

// NewAnalyticsService creates a new analytics service
func NewAnalyticsService(db *gorm.DB, influxURL, influxToken, influxOrg, influxBucket string, redisClient *redis.Client) *AnalyticsService {
    client := influxdb2.NewClient(influxURL, influxToken)
    writeAPI := client.WriteAPIBlocking(influxOrg, influxBucket)
    queryAPI := client.QueryAPI(influxOrg)
    
    return &AnalyticsService{
        db:        db,
        influx:    client,
        influxAPI: writeAPI,
        queryAPI:  queryAPI,
        redis:     redisClient,
        mlPredictor: &MLPredictor{
            trafficCache: &TrafficCache{
                patterns: make(map[string]*TrafficPattern),
            },
        },
    }
}

// RecordTraffic records traffic data point
func (s *AnalyticsService) RecordTraffic(ctx context.Context, clientID, inboundID string, upload, download int64) error {
    point := influxdb2.NewPoint("traffic",
        map[string]string{
            "client_id":  clientID,
            "inbound_id": inboundID,
        },
        map[string]interface{}{
            "upload":   upload,
            "download": download,
            "total":    upload + download,
        },
        time.Now())
    
    if err := s.influxAPI.WritePoint(ctx, point); err != nil {
        return fmt.Errorf("failed to write traffic point: %w", err)
    }
    
    // Update cache for predictions
    s.updateTrafficPattern(clientID, upload, download)
    
    // Update Redis for real-time dashboard
    key := fmt.Sprintf("traffic:%s:%s", clientID, time.Now().Format("2006-01-02"))
    s.redis.HIncrBy(ctx, key, "upload", upload)
    s.redis.HIncrBy(ctx, key, "download", download)
    s.redis.Expire(ctx, key, 7*24*time.Hour)
    
    return nil
}

// GetTrafficStats retrieves traffic statistics
func (s *AnalyticsService) GetTrafficStats(ctx context.Context, clientID string, period time.Duration) (*TrafficStats, error) {
    endTime := time.Now()
    startTime := endTime.Add(-period)
    
    query := fmt.Sprintf(`
        from(bucket: "vortex")
        |> range(start: %s, stop: %s)
        |> filter(fn: (r) => r["_measurement"] == "traffic")
        |> filter(fn: (r) => r["client_id"] == "%s")
        |> filter(fn: (r) => r["_field"] == "upload" or r["_field"] == "download" or r["_field"] == "total")
        |> aggregateWindow(every: 1h, fn: sum, createEmpty: false)
        |> yield(name: "traffic")
    `, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), clientID)
    
    result, err := s.queryAPI.Query(ctx, query)
    if err != nil {
        return nil, fmt.Errorf("failed to query traffic stats: %w", err)
    }
    
    stats := &TrafficStats{
        ClientID:  clientID,
        Period:    period,
        StartTime: startTime,
        EndTime:   endTime,
        Points:    []TrafficPoint{},
    }
    
    for result.Next() {
        record := result.Record()
        point := TrafficPoint{
            Time:  record.Time(),
            Field: record.Field(),
            Value: record.Value().(float64),
        }
        stats.Points = append(stats.Points, point)
    }
    
    if result.Err() != nil {
        return nil, fmt.Errorf("query error: %w", result.Err())
    }
    
    return stats, nil
}

// PredictTraffic uses ML to predict future traffic
func (s *AnalyticsService) PredictTraffic(ctx context.Context, clientID string, days int) (*TrafficPrediction, error) {
    pattern, exists := s.mlPredictor.trafficCache.patterns[clientID]
    if !exists {
        return nil, fmt.Errorf("no traffic pattern found for client %s", clientID)
    }
    
    // Simple prediction based on historical patterns
    // In production, this would use TensorFlow or similar
    prediction := &TrafficPrediction{
        ClientID: clientID,
        Days:     days,
        Predictions: []DailyPrediction{},
    }
    
    for i := 0; i < days; i++ {
        date := time.Now().AddDate(0, 0, i+1)
        
        // Calculate predicted traffic based on patterns
        baseTraffic := pattern.AvgBandwidth * 24 * 3600 // Convert to daily
        variance := baseTraffic * 0.2 // 20% variance
        
        // Add day-of-week factor
        dayFactor := s.getDayOfWeekFactor(date.Weekday())
        
        predictedTraffic := baseTraffic * dayFactor
        
        prediction.Predictions = append(prediction.Predictions, DailyPrediction{
            Date:       date,
            Traffic:    int64(predictedTraffic),
            Confidence: pattern.Consistency,
            Upper:      int64(predictedTraffic + variance),
            Lower:      int64(math.Max(0, predictedTraffic-variance)),
        })
    }
    
    return prediction, nil
}

// GetAnomalies detects traffic anomalies
func (s *AnalyticsService) GetAnomalies(ctx context.Context, threshold float64) ([]Anomaly, error) {
    query := fmt.Sprintf(`
        from(bucket: "vortex")
        |> range(start: -24h)
        |> filter(fn: (r) => r["_measurement"] == "traffic")
        |> filter(fn: (r) => r["_field"] == "total")
        |> aggregateWindow(every: 5m, fn: sum, createEmpty: false)
        |> movingAverage(n: 12)
        |> difference()
    `)
    
    result, err := s.queryAPI.Query(ctx, query)
    if err != nil {
        return nil, fmt.Errorf("failed to query anomalies: %w", err)
    }
    
    anomalies := []Anomaly{}
    
    for result.Next() {
        record := result.Record()
        value := record.Value().(float64)
        
        if math.Abs(value) > threshold {
            anomaly := Anomaly{
                ClientID:  record.ValueByKey("client_id").(string),
                Timestamp: record.Time(),
                Value:     value,
                Type:      s.classifyAnomaly(value),
                Severity:  s.calculateSeverity(value, threshold),
            }
            anomalies = append(anomalies, anomaly)
        }
    }
    
    return anomalies, nil
}

// GetSystemMetrics retrieves system-wide metrics
func (s *AnalyticsService) GetSystemMetrics(ctx context.Context) (*SystemMetrics, error) {
    metrics := &SystemMetrics{
        Timestamp: time.Now(),
    }
    
    // Get active users count
    var activeUsers int64
    s.db.Model(&models.Client{}).Where("enable = ? AND (expiry_time IS NULL OR expiry_time > ?)", true, time.Now()).Count(&activeUsers)
    metrics.ActiveUsers = int(activeUsers)
    
    // Get total traffic from Redis
    totalUpload, _ := s.redis.Get(ctx, "metrics:total:upload").Int64()
    totalDownload, _ := s.redis.Get(ctx, "metrics:total:download").Int64()
    metrics.TotalTraffic = totalUpload + totalDownload
    
    // Get connection count
    connections, _ := s.redis.SCard(ctx, "active:connections").Result()
    metrics.ActiveConnections = int(connections)
    
    // Calculate bandwidth usage
    bandwidthQuery := `
        from(bucket: "vortex")
        |> range(start: -5m)
        |> filter(fn: (r) => r["_measurement"] == "traffic")
        |> filter(fn: (r) => r["_field"] == "total")
        |> sum()
    `
    
    result, err := s.queryAPI.Query(ctx, bandwidthQuery)
    if err == nil && result.Next() {
        record := result.Record()
        if val, ok := record.Value().(float64); ok {
            metrics.BandwidthUsage = val / 300 // Convert to per second
        }
    }
    
    // Get server resources
    metrics.CPUUsage = s.getCPUUsage()
    metrics.MemoryUsage = s.getMemoryUsage()
    metrics.DiskUsage = s.getDiskUsage()
    
    return metrics, nil
}

// GenerateReport generates analytics report
func (s *AnalyticsService) GenerateReport(ctx context.Context, reportType string, period time.Duration) (*Report, error) {
    report := &Report{
        ID:        generateReportID(),
        Type:      reportType,
        Period:    period,
        Generated: time.Now(),
        Sections:  []ReportSection{},
    }
    
    switch reportType {
    case "traffic":
        report.Sections = append(report.Sections, s.generateTrafficSection(ctx, period))
    case "usage":
        report.Sections = append(report.Sections, s.generateUsageSection(ctx, period))
    case "performance":
        report.Sections = append(report.Sections, s.generatePerformanceSection(ctx, period))
    case "comprehensive":
        report.Sections = append(report.Sections, 
            s.generateTrafficSection(ctx, period),
            s.generateUsageSection(ctx, period),
            s.generatePerformanceSection(ctx, period),
            s.generateSecuritySection(ctx, period),
        )
    }
    
    // Store report
    reportJSON, _ := json.Marshal(report)
    s.redis.Set(ctx, fmt.Sprintf("report:%s", report.ID), reportJSON, 24*time.Hour)
    
    return report, nil
}

// Helper functions
func (s *AnalyticsService) updateTrafficPattern(clientID string, upload, download int64) {
    pattern, exists := s.mlPredictor.trafficCache.patterns[clientID]
    if !exists {
        pattern = &TrafficPattern{
            UserID:      clientID,
            LastUpdated: time.Now(),
        }
        s.mlPredictor.trafficCache.patterns[clientID] = pattern
    }
    
    // Update moving average
    alpha := 0.3 // Smoothing factor
    currentBandwidth := float64(upload+download) / 300 // 5-minute window
    pattern.AvgBandwidth = alpha*currentBandwidth + (1-alpha)*pattern.AvgBandwidth
    
    // Update peak hours
    currentHour := time.Now().Hour()
    pattern.PeakHours = updatePeakHours(pattern.PeakHours, currentHour, currentBandwidth)
    
    // Calculate consistency
    pattern.Consistency = calculateConsistency(pattern)
    pattern.LastUpdated = time.Now()
}

func (s *AnalyticsService) getDayOfWeekFactor(day time.Weekday) float64 {
    factors := map[time.Weekday]float64{
        time.Monday:    0.9,
        time.Tuesday:   0.95,
        time.Wednesday: 1.0,
        time.Thursday:  1.05,
        time.Friday:    1.15,
        time.Saturday:  1.3,
        time.Sunday:    1.25,
    }
    return factors[day]
}

func (s *AnalyticsService) classifyAnomaly(value float64) string {
    if value > 0 {
        return "spike"
    }
    return "drop"
}

func (s *AnalyticsService) calculateSeverity(value, threshold float64) string {
    ratio := math.Abs(value) / threshold
    switch {
    case ratio < 1.5:
        return "low"
    case ratio < 2.5:
        return "medium"
    case ratio < 4:
        return "high"
    default:
        return "critical"
    }
}

// API Handlers
func (s *AnalyticsService) Overview(c *fiber.Ctx) error {
    ctx := c.Context()
    
    // Get time range from query
    period := c.Query("period", "24h")
    duration, err := time.ParseDuration(period)
    if err != nil {
        duration = 24 * time.Hour
    }
    
    // Collect overview data
    overview := &AnalyticsOverview{
        Period: duration,
    }
    
    // System metrics
    overview.SystemMetrics, _ = s.GetSystemMetrics(ctx)
    
    // Top users by traffic
    topUsersQuery := fmt.Sprintf(`
        from(bucket: "vortex")
        |> range(start: -%s)
        |> filter(fn: (r) => r["_measurement"] == "traffic")
        |> filter(fn: (r) => r["_field"] == "total")
        |> group(columns: ["client_id"])
        |> sum()
        |> sort(desc: true)
        |> limit(n: 10)
    `, period)
    
    result, err := s.queryAPI.Query(ctx, topUsersQuery)
    if err == nil {
        overview.TopUsers = []UserTraffic{}
        for result.Next() {
            record := result.Record()
            overview.TopUsers = append(overview.TopUsers, UserTraffic{
                ClientID: record.ValueByKey("client_id").(string),
                Traffic:  record.Value().(float64),
            })
        }
    }
    
    // Traffic trend
    overview.TrafficTrend = s.calculateTrafficTrend(ctx, duration)
    
    // Anomalies
    overview.Anomalies, _ = s.GetAnomalies(ctx, 1000000) // 1MB threshold
    
    return c.JSON(overview)
}

func (s *AnalyticsService) Traffic(c *fiber.Ctx) error {
    ctx := c.Context()
    
    clientID := c.Query("client_id")
    period := c.Query("period", "24h")
    duration, _ := time.ParseDuration(period)
    
    if clientID != "" {
        stats, err := s.GetTrafficStats(ctx, clientID, duration)
        if err != nil {
            return c.Status(500).JSON(fiber.Map{"error": err.Error()})
        }
        return c.JSON(stats)
    }
    
    // Global traffic stats
    globalStats, err := s.getGlobalTrafficStats(ctx, duration)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }
    
    return c.JSON(globalStats)
}

func (s *AnalyticsService) Performance(c *fiber.Ctx) error {
    ctx := c.Context()
    
    performance := &PerformanceMetrics{
        Timestamp: time.Now(),
    }
    
    // Response time metrics
    responseQuery := `
        from(bucket: "vortex")
        |> range(start: -1h)
        |> filter(fn: (r) => r["_measurement"] == "response_time")
        |> aggregateWindow(every: 5m, fn: mean, createEmpty: false)
    `
    
    result, _ := s.queryAPI.Query(ctx, responseQuery)
    performance.ResponseTimes = []ResponseTime{}
    
    for result.Next() {
        record := result.Record()
        performance.ResponseTimes = append(performance.ResponseTimes, ResponseTime{
            Endpoint: record.ValueByKey("endpoint").(string),
            Time:     record.Time(),
            Duration: record.Value().(float64),
        })
    }
    
    // Error rates
    errorQuery := `
        from(bucket: "vortex")
        |> range(start: -1h)
        |> filter(fn: (r) => r["_measurement"] == "errors")
        |> aggregateWindow(every: 5m, fn: count, createEmpty: false)
    `
    
    errorResult, _ := s.queryAPI.Query(ctx, errorQuery)
    performance.ErrorRates = []ErrorRate{}
    
    for errorResult.Next() {
        record := errorResult.Record()
        performance.ErrorRates = append(performance.ErrorRates, ErrorRate{
            Type:  record.ValueByKey("type").(string),
            Count: int(record.Value().(float64)),
            Time:  record.Time(),
        })
    }
    
    return c.JSON(performance)
}

func (s *AnalyticsService) Predictions(c *fiber.Ctx) error {
    ctx := c.Context()
    
    clientID := c.Query("client_id")
    days := c.QueryInt("days", 7)
    
    if clientID == "" {
        return c.Status(400).JSON(fiber.Map{"error": "client_id is required"})
    }
    
    prediction, err := s.PredictTraffic(ctx, clientID, days)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }
    
    return c.JSON(prediction)
}

// Types
type TrafficStats struct {
    ClientID  string         `json:"client_id"`
    Period    time.Duration  `json:"period"`
    StartTime time.Time      `json:"start_time"`
    EndTime   time.Time      `json:"end_time"`
    Points    []TrafficPoint `json:"points"`
}

type TrafficPoint struct {
    Time  time.Time `json:"time"`
    Field string    `json:"field"`
    Value float64   `json:"value"`
}

type TrafficPrediction struct {
    ClientID    string             `json:"client_id"`
    Days        int                `json:"days"`
    Predictions []DailyPrediction  `json:"predictions"`
}

type DailyPrediction struct {
    Date       time.Time `json:"date"`
    Traffic    int64     `json:"traffic"`
    Confidence float64   `json:"confidence"`
    Upper      int64     `json:"upper_bound"`
    Lower      int64     `json:"lower_bound"`
}

type Anomaly struct {
    ClientID  string    `json:"client_id"`
    Timestamp time.Time `json:"timestamp"`
    Value     float64   `json:"value"`
    Type      string    `json:"type"`
    Severity  string    `json:"severity"`
}

type SystemMetrics struct {
    Timestamp         time.Time `json:"timestamp"`
    ActiveUsers       int       `json:"active_users"`
    ActiveConnections int       `json:"active_connections"`
    TotalTraffic      int64     `json:"total_traffic"`
    BandwidthUsage    float64   `json:"bandwidth_usage"`
    CPUUsage          float64   `json:"cpu_usage"`
    MemoryUsage       float64   `json:"memory_usage"`
    DiskUsage         float64   `json:"disk_usage"`
}

type Report struct {
    ID        string          `json:"id"`
    Type      string          `json:"type"`
    Period    time.Duration   `json:"period"`
    Generated time.Time       `json:"generated"`
    Sections  []ReportSection `json:"sections"`
}

type ReportSection struct {
    Title   string                 `json:"title"`
    Type    string                 `json:"type"`
    Data    map[string]interface{} `json:"data"`
    Charts  []ChartConfig          `json:"charts"`
}

type ChartConfig struct {
    Type    string                 `json:"type"`
    Title   string                 `json:"title"`
    Data    interface{}            `json:"data"`
    Options map[string]interface{} `json:"options"`
}

type AnalyticsOverview struct {
    Period         time.Duration   `json:"period"`
    SystemMetrics  *SystemMetrics  `json:"system_metrics"`
    TopUsers       []UserTraffic   `json:"top_users"`
    TrafficTrend   []TrendPoint    `json:"traffic_trend"`
    Anomalies      []Anomaly       `json:"anomalies"`
}

type UserTraffic struct {
    ClientID string  `json:"client_id"`
    Traffic  float64 `json:"traffic"`
}

type TrendPoint struct {
    Time  time.Time `json:"time"`
    Value float64   `json:"value"`
    Trend string    `json:"trend"`
}

type PerformanceMetrics struct {
    Timestamp     time.Time      `json:"timestamp"`
    ResponseTimes []ResponseTime `json:"response_times"`
    ErrorRates    []ErrorRate    `json:"error_rates"`
}

type ResponseTime struct {
    Endpoint string    `json:"endpoint"`
    Time     time.Time `json:"time"`
    Duration float64   `json:"duration"`
}

type ErrorRate struct {
    Type  string    `json:"type"`
    Count int       `json:"count"`
    Time  time.Time `json:"time"`
}