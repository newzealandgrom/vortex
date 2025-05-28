// main.go - VortexPanel Backend Core
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/gofiber/fiber/v2/middleware/logger"
    "github.com/gofiber/fiber/v2/middleware/recover"
    "github.com/gofiber/websocket/v2"
    "github.com/vortexpanel/core/config"
    "github.com/vortexpanel/core/database"
    "github.com/vortexpanel/core/services"
)

func main() {
    // Load configuration
    cfg := config.Load()
    
    // Initialize database
    db, err := database.Initialize(cfg.Database)
    if err != nil {
        log.Fatal("Failed to initialize database:", err)
    }
    defer db.Close()
    
    // Initialize services
    serviceManager := services.NewManager(db, cfg)
    
    // Create fiber app
    app := fiber.New(fiber.Config{
        AppName:               "VortexPanel",
        ServerHeader:          "VortexPanel",
        DisableStartupMessage: false,
        EnablePrintRoutes:     cfg.Debug,
        ErrorHandler:          errorHandler,
    })
    
    // Middleware
    setupMiddleware(app, cfg)
    
    // Routes
    setupRoutes(app, serviceManager)
    
    // Start server
    go func() {
        if err := app.Listen(cfg.Server.Address); err != nil {
            log.Fatal("Failed to start server:", err)
        }
    }()
    
    // Graceful shutdown
    waitForShutdown(app, serviceManager)
}

func setupMiddleware(app *fiber.App, cfg *config.Config) {
    app.Use(recover.New())
    app.Use(logger.New())
    app.Use(cors.New(cors.Config{
        AllowOrigins:     cfg.CORS.AllowedOrigins,
        AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders:     "Origin,Content-Type,Accept,Authorization",
        AllowCredentials: true,
    }))
}

func setupRoutes(app *fiber.App, sm *services.Manager) {
    // API routes
    api := app.Group("/api/v1")
    
    // Authentication
    auth := api.Group("/auth")
    auth.Post("/login", sm.Auth.Login)
    auth.Post("/logout", sm.Auth.Logout)
    auth.Post("/refresh", sm.Auth.RefreshToken)
    auth.Post("/2fa/setup", sm.Auth.Setup2FA)
    auth.Post("/2fa/verify", sm.Auth.Verify2FA)
    
    // Protected routes
    protected := api.Use(sm.Auth.Middleware())
    
    // Users
    users := protected.Group("/users")
    users.Get("/", sm.Users.List)
    users.Post("/", sm.Users.Create)
    users.Get("/:id", sm.Users.Get)
    users.Put("/:id", sm.Users.Update)
    users.Delete("/:id", sm.Users.Delete)
    users.Get("/:id/traffic", sm.Users.GetTraffic)
    
    // Inbounds
    inbounds := protected.Group("/inbounds")
    inbounds.Get("/", sm.Inbounds.List)
    inbounds.Post("/", sm.Inbounds.Create)
    inbounds.Get("/:id", sm.Inbounds.Get)
    inbounds.Put("/:id", sm.Inbounds.Update)
    inbounds.Delete("/:id", sm.Inbounds.Delete)
    inbounds.Post("/:id/restart", sm.Inbounds.Restart)
    
    // Analytics
    analytics := protected.Group("/analytics")
    analytics.Get("/overview", sm.Analytics.Overview)
    analytics.Get("/traffic", sm.Analytics.Traffic)
    analytics.Get("/performance", sm.Analytics.Performance)
    analytics.Get("/predictions", sm.Analytics.Predictions)
    
    // System
    system := protected.Group("/system")
    system.Get("/status", sm.System.Status)
    system.Get("/health", sm.System.Health)
    system.Post("/backup", sm.System.Backup)
    system.Post("/restore", sm.System.Restore)
    system.Get("/logs", sm.System.Logs)
    
    // WebSocket for real-time updates
    app.Get("/ws", websocket.New(sm.WebSocket.Handler))
    
    // GraphQL endpoint
    app.Post("/graphql", sm.GraphQL.Handler)
    app.Get("/graphql", sm.GraphQL.Playground)
}

func errorHandler(c *fiber.Ctx, err error) error {
    code := fiber.StatusInternalServerError
    message := "Internal Server Error"
    
    if e, ok := err.(*fiber.Error); ok {
        code = e.Code
        message = e.Message
    }
    
    return c.Status(code).JSON(fiber.Map{
        "error": message,
        "code":  code,
        "time":  time.Now().Unix(),
    })
}

func waitForShutdown(app *fiber.App, sm *services.Manager) {
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    log.Println("Shutting down server...")
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // Shutdown services
    if err := sm.Shutdown(ctx); err != nil {
        log.Printf("Service shutdown error: %v", err)
    }
    
    // Shutdown server
    if err := app.ShutdownWithContext(ctx); err != nil {
        log.Printf("Server shutdown error: %v", err)
    }
    
    log.Println("Server shutdown complete")
}

// models/user.go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type User struct {
    ID            uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
    Email         string         `gorm:"uniqueIndex;not null" json:"email"`
    Username      string         `gorm:"uniqueIndex;not null" json:"username"`
    PasswordHash  string         `gorm:"not null" json:"-"`
    Role          UserRole       `gorm:"not null;default:'user'" json:"role"`
    Status        UserStatus     `gorm:"not null;default:'active'" json:"status"`
    TwoFactorAuth *TwoFactorAuth `gorm:"constraint:OnDelete:CASCADE" json:"two_factor_auth,omitempty"`
    Profile       *UserProfile   `gorm:"constraint:OnDelete:CASCADE" json:"profile,omitempty"`
    Subscription  *Subscription  `gorm:"constraint:OnDelete:CASCADE" json:"subscription,omitempty"`
    Clients       []Client       `gorm:"constraint:OnDelete:CASCADE" json:"clients,omitempty"`
    CreatedAt     time.Time      `json:"created_at"`
    UpdatedAt     time.Time      `json:"updated_at"`
    DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

type UserRole string

const (
    RoleAdmin     UserRole = "admin"
    RoleModerator UserRole = "moderator"
    RoleUser      UserRole = "user"
)

type UserStatus string

const (
    StatusActive    UserStatus = "active"
    StatusSuspended UserStatus = "suspended"
    StatusDeleted   UserStatus = "deleted"
)

type TwoFactorAuth struct {
    ID         uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
    UserID     uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
    Secret     string     `gorm:"not null" json:"-"`
    BackupCodes []string  `gorm:"type:text[]" json:"-"`
    Enabled    bool       `gorm:"default:false" json:"enabled"`
    CreatedAt  time.Time  `json:"created_at"`
    UpdatedAt  time.Time  `json:"updated_at"`
}

type UserProfile struct {
    ID              uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
    UserID          uuid.UUID  `gorm:"type:uuid;not null;uniqueIndex" json:"user_id"`
    FirstName       string     `json:"first_name"`
    LastName        string     `json:"last_name"`
    Avatar          string     `json:"avatar"`
    Language        string     `gorm:"default:'en'" json:"language"`
    Timezone        string     `gorm:"default:'UTC'" json:"timezone"`
    NotificationPrefs JSONMap  `gorm:"type:jsonb" json:"notification_prefs"`
    CreatedAt       time.Time  `json:"created_at"`
    UpdatedAt       time.Time  `json:"updated_at"`
}

// models/client.go
package models

import (
    "time"
    "github.com/google/uuid"
)

type Client struct {
    ID              uuid.UUID       `gorm:"type:uuid;primary_key" json:"id"`
    UserID          uuid.UUID       `gorm:"type:uuid;not null" json:"user_id"`
    InboundID       uuid.UUID       `gorm:"type:uuid;not null" json:"inbound_id"`
    Email           string          `gorm:"not null" json:"email"`
    UUID            string          `gorm:"not null" json:"uuid"`
    Password        string          `json:"password,omitempty"`
    Flow            string          `json:"flow,omitempty"`
    LimitIP         int             `gorm:"default:0" json:"limit_ip"`
    TotalGB         int64           `gorm:"default:0" json:"total_gb"`
    ExpiryTime      *time.Time      `json:"expiry_time,omitempty"`
    Enable          bool            `gorm:"default:true" json:"enable"`
    TgID            string          `json:"tg_id,omitempty"`
    SubID           string          `json:"sub_id,omitempty"`
    Reset           int             `gorm:"default:0" json:"reset"`
    TrafficStats    []TrafficStat   `gorm:"constraint:OnDelete:CASCADE" json:"traffic_stats,omitempty"`
    ConnectionLogs  []ConnectionLog `gorm:"constraint:OnDelete:CASCADE" json:"connection_logs,omitempty"`
    CreatedAt       time.Time       `json:"created_at"`
    UpdatedAt       time.Time       `json:"updated_at"`
}

type TrafficStat struct {
    ID         uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
    ClientID   uuid.UUID `gorm:"type:uuid;not null" json:"client_id"`
    Download   int64     `json:"download"`
    Upload     int64     `json:"upload"`
    Total      int64     `json:"total"`
    RecordedAt time.Time `json:"recorded_at"`
}

type ConnectionLog struct {
    ID         uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
    ClientID   uuid.UUID `gorm:"type:uuid;not null" json:"client_id"`
    IP         string    `json:"ip"`
    Country    string    `json:"country"`
    City       string    `json:"city"`
    UserAgent  string    `json:"user_agent"`
    ConnectedAt time.Time `json:"connected_at"`
    DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
}

// models/inbound.go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/datatypes"
)

type Inbound struct {
    ID          uuid.UUID           `gorm:"type:uuid;primary_key" json:"id"`
    UserID      uuid.UUID           `gorm:"type:uuid;not null" json:"user_id"`
    Remark      string              `gorm:"not null" json:"remark"`
    Enable      bool                `gorm:"default:true" json:"enable"`
    Protocol    Protocol            `gorm:"not null" json:"protocol"`
    Settings    datatypes.JSON      `gorm:"type:jsonb;not null" json:"settings"`
    StreamSettings datatypes.JSON   `gorm:"type:jsonb;not null" json:"stream_settings"`
    Tag         string              `gorm:"uniqueIndex;not null" json:"tag"`
    Sniffing    datatypes.JSON      `gorm:"type:jsonb" json:"sniffing"`
    Listen      string              `json:"listen"`
    Port        int                 `gorm:"not null" json:"port"`
    Clients     []Client            `gorm:"constraint:OnDelete:CASCADE" json:"clients,omitempty"`
    Stats       []InboundStat       `gorm:"constraint:OnDelete:CASCADE" json:"stats,omitempty"`
    CreatedAt   time.Time           `json:"created_at"`
    UpdatedAt   time.Time           `json:"updated_at"`
}

type Protocol string

const (
    ProtocolVMess       Protocol = "vmess"
    ProtocolVLESS       Protocol = "vless"
    ProtocolTrojan      Protocol = "trojan"
    ProtocolShadowsocks Protocol = "shadowsocks"
    ProtocolDokodemo    Protocol = "dokodemo-door"
    ProtocolSocks       Protocol = "socks"
    ProtocolHTTP        Protocol = "http"
    ProtocolWireGuard   Protocol = "wireguard"
)

type InboundStat struct {
    ID         uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
    InboundID  uuid.UUID `gorm:"type:uuid;not null" json:"inbound_id"`
    Download   int64     `json:"download"`
    Upload     int64     `json:"upload"`
    Total      int64     `json:"total"`
    RecordedAt time.Time `json:"recorded_at"`
}

// services/auth.go
package services

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "time"
    
    "github.com/gofiber/fiber/v2"
    "github.com/golang-jwt/jwt/v5"
    "github.com/pquerna/otp/totp"
    "golang.org/x/crypto/bcrypt"
    "github.com/vortexpanel/core/models"
)

type AuthService struct {
    db          *gorm.DB
    jwtSecret   []byte
    tokenExpiry time.Duration
}

func NewAuthService(db *gorm.DB, secret string) *AuthService {
    return &AuthService{
        db:          db,
        jwtSecret:   []byte(secret),
        tokenExpiry: 24 * time.Hour,
    }
}

func (s *AuthService) Login(c *fiber.Ctx) error {
    var req struct {
        Username string `json:"username" validate:"required"`
        Password string `json:"password" validate:"required"`
        TOTPCode string `json:"totp_code"`
    }
    
    if err := c.BodyParser(&req); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
    }
    
    // Find user
    var user models.User
    if err := s.db.Preload("TwoFactorAuth").Where("username = ? OR email = ?", req.Username, req.Username).First(&user).Error; err != nil {
        return fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
    }
    
    // Verify password
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
        return fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
    }
    
    // Check 2FA
    if user.TwoFactorAuth != nil && user.TwoFactorAuth.Enabled {
        if req.TOTPCode == "" {
            return c.Status(fiber.StatusOK).JSON(fiber.Map{
                "requires_2fa": true,
                "message": "Please provide 2FA code",
            })
        }
        
        if !totp.Validate(req.TOTPCode, user.TwoFactorAuth.Secret) {
            return fiber.NewError(fiber.StatusUnauthorized, "Invalid 2FA code")
        }
    }
    
    // Generate tokens
    accessToken, refreshToken, err := s.generateTokens(user.ID)
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate tokens")
    }
    
    // Save refresh token
    if err := s.saveRefreshToken(user.ID, refreshToken); err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to save session")
    }
    
    return c.JSON(fiber.Map{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
        "user":          user,
    })
}

func (s *AuthService) generateTokens(userID uuid.UUID) (string, string, error) {
    // Access token
    accessClaims := jwt.MapClaims{
        "user_id": userID.String(),
        "exp":     time.Now().Add(15 * time.Minute).Unix(),
        "iat":     time.Now().Unix(),
    }
    
    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    accessTokenString, err := accessToken.SignedString(s.jwtSecret)
    if err != nil {
        return "", "", err
    }
    
    // Refresh token
    refreshToken := make([]byte, 32)
    if _, err := rand.Read(refreshToken); err != nil {
        return "", "", err
    }
    
    return accessTokenString, base64.URLEncoding.EncodeToString(refreshToken), nil
}

func (s *AuthService) Middleware() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Get token from header
        authHeader := c.Get("Authorization")
        if authHeader == "" {
            return fiber.NewError(fiber.StatusUnauthorized, "Missing authorization header")
        }
        
        // Parse token
        tokenString := authHeader[7:] // Remove "Bearer "
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, errors.New("unexpected signing method")
            }
            return s.jwtSecret, nil
        })
        
        if err != nil || !token.Valid {
            return fiber.NewError(fiber.StatusUnauthorized, "Invalid token")
        }
        
        // Get user ID from claims
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            return fiber.NewError(fiber.StatusUnauthorized, "Invalid token claims")
        }
        
        userID, ok := claims["user_id"].(string)
        if !ok {
            return fiber.NewError(fiber.StatusUnauthorized, "Invalid user ID in token")
        }
        
        // Add user ID to context
        c.Locals("user_id", userID)
        
        return c.Next()
    }
}

// services/xray.go
package services

import (
    "context"
    "encoding/json"
    "fmt"
    "sync"
    
    "github.com/vortexpanel/core/models"
    "github.com/vortexpanel/core/xray"
)

type XrayService struct {
    mu         sync.RWMutex
    instances  map[string]*xray.Instance
    db         *gorm.DB
    configPath string
}

func NewXrayService(db *gorm.DB, configPath string) *XrayService {
    return &XrayService{
        instances:  make(map[string]*xray.Instance),
        db:         db,
        configPath: configPath,
    }
}

func (s *XrayService) GenerateConfig(inbounds []models.Inbound) (*xray.Config, error) {
    config := &xray.Config{
        Log: &xray.LogConfig{
            Access:   "./access.log",
            Error:    "./error.log",
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
            },
        },
        Inbounds:  []xray.InboundConfig{},
        Outbounds: s.getDefaultOutbounds(),
        Routing:   s.getDefaultRouting(),
    }
    
    // Add API inbound
    config.Inbounds = append(config.Inbounds, xray.InboundConfig{
        Tag:      "api",
        Port:     62789,
        Listen:   "127.0.0.1",
        Protocol: "dokodemo-door",
        Settings: json.RawMessage(`{"address": "127.0.0.1"}`),
    })
    
    // Add user inbounds
    for _, inbound := range inbounds {
        if !inbound.Enable {
            continue
        }
        
        inboundConfig := xray.InboundConfig{
            Tag:      inbound.Tag,
            Port:     inbound.Port,
            Listen:   inbound.Listen,
            Protocol: string(inbound.Protocol),
            Settings: inbound.Settings,
            StreamSettings: inbound.StreamSettings,
            Sniffing: inbound.Sniffing,
        }
        
        config.Inbounds = append(config.Inbounds, inboundConfig)
    }
    
    return config, nil
}

func (s *XrayService) Restart() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    // Stop all instances
    for id, instance := range s.instances {
        if err := instance.Stop(); err != nil {
            return fmt.Errorf("failed to stop instance %s: %w", id, err)
        }
    }
    
    // Clear instances
    s.instances = make(map[string]*xray.Instance)
    
    // Get all enabled inbounds
    var inbounds []models.Inbound
    if err := s.db.Where("enable = ?", true).Find(&inbounds).Error; err != nil {
        return fmt.Errorf("failed to get inbounds: %w", err)
    }
    
    // Generate config
    config, err := s.GenerateConfig(inbounds)
    if err != nil {
        return fmt.Errorf("failed to generate config: %w", err)
    }
    
    // Save config
    if err := s.saveConfig(config); err != nil {
        return fmt.Errorf("failed to save config: %w", err)
    }
    
    // Start new instance
    instance, err := xray.NewInstance(s.configPath)
    if err != nil {
        return fmt.Errorf("failed to create instance: %w", err)
    }
    
    if err := instance.Start(); err != nil {
        return fmt.Errorf("failed to start instance: %w", err)
    }
    
    s.instances["main"] = instance
    
    return nil
}

func (s *XrayService) getDefaultOutbounds() []xray.OutboundConfig {
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
    }
}

func (s *XrayService) getDefaultRouting() *xray.RoutingConfig {
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
                IP:          []string{"geoip:private"},
                OutboundTag: "blocked",
            },
            {
                Type:        "field",
                Protocol:    []string{"bittorrent"},
                OutboundTag: "blocked",
            },
        },
    }
}