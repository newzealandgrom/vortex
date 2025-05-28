// services/auth/main.go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "github.com/go-webauthn/webauthn/webauthn"
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/gofiber/fiber/v2/middleware/logger"
    "github.com/gofiber/fiber/v2/middleware/recover"
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "github.com/pquerna/otp/totp"
    "github.com/redis/go-redis/v9"
    "golang.org/x/crypto/bcrypt"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)

// Models
type User struct {
    ID            uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
    Email         string         `gorm:"uniqueIndex;not null" json:"email"`
    Username      string         `gorm:"uniqueIndex;not null" json:"username"`
    PasswordHash  string         `gorm:"not null" json:"-"`
    Role          string         `gorm:"not null;default:'user'" json:"role"`
    Status        string         `gorm:"not null;default:'active'" json:"status"`
    TwoFactorAuth *TwoFactorAuth `gorm:"constraint:OnDelete:CASCADE" json:"two_factor_auth,omitempty"`
    WebAuthnCreds []WebAuthnCred `gorm:"constraint:OnDelete:CASCADE" json:"-"`
    OAuthAccounts []OAuthAccount `gorm:"constraint:OnDelete:CASCADE" json:"oauth_accounts,omitempty"`
    Sessions      []Session      `gorm:"constraint:OnDelete:CASCADE" json:"-"`
    CreatedAt     time.Time      `json:"created_at"`
    UpdatedAt     time.Time      `json:"updated_at"`
}

type TwoFactorAuth struct {
    ID          uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
    UserID      uuid.UUID `gorm:"type:uuid;not null" json:"user_id"`
    Secret      string    `gorm:"not null" json:"-"`
    BackupCodes []string  `gorm:"type:text[]" json:"-"`
    Enabled     bool      `gorm:"default:false" json:"enabled"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

type WebAuthnCred struct {
    ID              uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
    UserID          uuid.UUID `gorm:"type:uuid;not null" json:"user_id"`
    CredentialID    []byte    `gorm:"not null" json:"credential_id"`
    PublicKey       []byte    `gorm:"not null" json:"public_key"`
    AttestationType string    `json:"attestation_type"`
    Transport       []string  `gorm:"type:text[]" json:"transport"`
    Flags           uint8     `json:"flags"`
    Authenticator   []byte    `json:"authenticator"`
    CreatedAt       time.Time `json:"created_at"`
}

type OAuthAccount struct {
    ID          uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
    UserID      uuid.UUID `gorm:"type:uuid;not null" json:"user_id"`
    Provider    string    `gorm:"not null" json:"provider"`
    ProviderID  string    `gorm:"not null" json:"provider_id"`
    AccessToken string    `json:"-"`
    Email       string    `json:"email"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

type Session struct {
    ID           uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
    UserID       uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
    RefreshToken string     `gorm:"uniqueIndex;not null" json:"-"`
    UserAgent    string     `json:"user_agent"`
    IP           string     `json:"ip"`
    ExpiresAt    time.Time  `json:"expires_at"`
    CreatedAt    time.Time  `json:"created_at"`
    LastUsedAt   time.Time  `json:"last_used_at"`
    RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// AuthService handles authentication
type AuthService struct {
    db              *gorm.DB
    redis           *redis.Client
    jwtSecret       []byte
    webAuthn        *webauthn.WebAuthn
    oauthConfigs    map[string]*oauth2.Config
    tokenExpiry     time.Duration
    refreshExpiry   time.Duration
}

// NewAuthService creates a new auth service
func NewAuthService(db *gorm.DB, redis *redis.Client, config *Config) (*AuthService, error) {
    // Initialize WebAuthn
    wconfig := &webauthn.Config{
        RPDisplayName: "VortexPanel",
        RPID:          config.WebAuthn.RPID,
        RPOrigin:      config.WebAuthn.RPOrigin,
        AuthenticatorSelection: protocol.AuthenticatorSelection{
            AuthenticatorAttachment: protocol.Platform,
            UserVerification:        protocol.VerificationRequired,
        },
    }
    
    webAuthn, err := webauthn.New(wconfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create WebAuthn: %w", err)
    }
    
    // Initialize OAuth configs
    oauthConfigs := make(map[string]*oauth2.Config)
    
    // Google OAuth
    if config.OAuth.Google.ClientID != "" {
        oauthConfigs["google"] = &oauth2.Config{
            ClientID:     config.OAuth.Google.ClientID,
            ClientSecret: config.OAuth.Google.ClientSecret,
            RedirectURL:  config.OAuth.Google.RedirectURL,
            Scopes:       []string{"email", "profile"},
            Endpoint:     google.Endpoint,
        }
    }
    
    return &AuthService{
        db:            db,
        redis:         redis,
        jwtSecret:     []byte(config.JWT.Secret),
        webAuthn:      webAuthn,
        oauthConfigs:  oauthConfigs,
        tokenExpiry:   15 * time.Minute,
        refreshExpiry: 7 * 24 * time.Hour,
    }, nil
}

// Login handles user login
func (s *AuthService) Login(c *fiber.Ctx) error {
    var req struct {
        Username string `json:"username" validate:"required"`
        Password string `json:"password" validate:"required"`
        TOTPCode string `json:"totp_code"`
        Remember bool   `json:"remember"`
    }
    
    if err := c.BodyParser(&req); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
    }
    
    // Find user
    var user User
    if err := s.db.Preload("TwoFactorAuth").Where("username = ? OR email = ?", req.Username, req.Username).First(&user).Error; err != nil {
        // Log failed attempt
        s.logFailedLogin(c, req.Username)
        return fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
    }
    
    // Check if user is active
    if user.Status != "active" {
        return fiber.NewError(fiber.StatusForbidden, "Account is not active")
    }
    
    // Verify password
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
        // Log failed attempt
        s.logFailedLogin(c, req.Username)
        
        // Check for brute force
        if s.checkBruteForce(c, user.ID) {
            return fiber.NewError(fiber.StatusTooManyRequests, "Too many failed attempts")
        }
        
        return fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
    }
    
    // Check 2FA
    if user.TwoFactorAuth != nil && user.TwoFactorAuth.Enabled {
        if req.TOTPCode == "" {
            return c.Status(fiber.StatusOK).JSON(fiber.Map{
                "requires_2fa": true,
                "message":      "Please provide 2FA code",
            })
        }
        
        // Verify TOTP
        if !totp.Validate(req.TOTPCode, user.TwoFactorAuth.Secret) {
            // Check backup codes
            if !s.checkBackupCode(&user, req.TOTPCode) {
                return fiber.NewError(fiber.StatusUnauthorized, "Invalid 2FA code")
            }
        }
    }
    
    // Generate tokens
    accessToken, refreshToken, err := s.generateTokens(&user)
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate tokens")
    }
    
    // Create session
    session := &Session{
        ID:           uuid.New(),
        UserID:       user.ID,
        RefreshToken: refreshToken,
        UserAgent:    c.Get("User-Agent"),
        IP:           c.IP(),
        ExpiresAt:    time.Now().Add(s.refreshExpiry),
        CreatedAt:    time.Now(),
        LastUsedAt:   time.Now(),
    }
    
    if req.Remember {
        session.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
    }
    
    if err := s.db.Create(session).Error; err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to create session")
    }
    
    // Clear failed attempts
    s.clearFailedAttempts(c, user.ID)
    
    // Log successful login
    s.logSuccessfulLogin(&user, c)
    
    return c.JSON(fiber.Map{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
        "expires_in":    int(s.tokenExpiry.Seconds()),
        "user":          user,
    })
}

// Setup2FA initializes 2FA for user
func (s *AuthService) Setup2FA(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    
    var user User
    if err := s.db.Preload("TwoFactorAuth").First(&user, userID).Error; err != nil {
        return fiber.NewError(fiber.StatusNotFound, "User not found")
    }
    
    // Check if already enabled
    if user.TwoFactorAuth != nil && user.TwoFactorAuth.Enabled {
        return fiber.NewError(fiber.StatusBadRequest, "2FA already enabled")
    }
    
    // Generate secret
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "VortexPanel",
        AccountName: user.Email,
    })
    
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate secret")
    }
    
    // Generate backup codes
    backupCodes := s.generateBackupCodes(8)
    
    // Save to database
    twoFA := &TwoFactorAuth{
        ID:          uuid.New(),
        UserID:      user.ID,
        Secret:      key.Secret(),
        BackupCodes: s.hashBackupCodes(backupCodes),
        Enabled:     false,
    }
    
    if user.TwoFactorAuth == nil {
        if err := s.db.Create(twoFA).Error; err != nil {
            return fiber.NewError(fiber.StatusInternalServerError, "Failed to save 2FA settings")
        }
    } else {
        twoFA.ID = user.TwoFactorAuth.ID
        if err := s.db.Save(twoFA).Error; err != nil {
            return fiber.NewError(fiber.StatusInternalServerError, "Failed to update 2FA settings")
        }
    }
    
    return c.JSON(fiber.Map{
        "secret":       key.Secret(),
        "qr_code":      key.URL(),
        "backup_codes": backupCodes,
    })
}

// Verify2FA confirms and enables 2FA
func (s *AuthService) Verify2FA(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    
    var req struct {
        Code string `json:"code" validate:"required"`
    }
    
    if err := c.BodyParser(&req); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
    }
    
    var user User
    if err := s.db.Preload("TwoFactorAuth").First(&user, userID).Error; err != nil {
        return fiber.NewError(fiber.StatusNotFound, "User not found")
    }
    
    if user.TwoFactorAuth == nil {
        return fiber.NewError(fiber.StatusBadRequest, "2FA not set up")
    }
    
    if user.TwoFactorAuth.Enabled {
        return fiber.NewError(fiber.StatusBadRequest, "2FA already enabled")
    }
    
    // Verify code
    if !totp.Validate(req.Code, user.TwoFactorAuth.Secret) {
        return fiber.NewError(fiber.StatusUnauthorized, "Invalid code")
    }
    
    // Enable 2FA
    user.TwoFactorAuth.Enabled = true
    if err := s.db.Save(user.TwoFactorAuth).Error; err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to enable 2FA")
    }
    
    return c.JSON(fiber.Map{
        "message": "2FA enabled successfully",
    })
}

// OAuth handlers
func (s *AuthService) OAuthLogin(c *fiber.Ctx) error {
    provider := c.Params("provider")
    
    config, ok := s.oauthConfigs[provider]
    if !ok {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid provider")
    }
    
    // Generate state
    state := uuid.New().String()
    
    // Store state in Redis
    ctx := context.Background()
    if err := s.redis.Set(ctx, fmt.Sprintf("oauth:state:%s", state), provider, 10*time.Minute).Err(); err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to store state")
    }
    
    // Redirect to OAuth provider
    url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
    return c.Redirect(url)
}

func (s *AuthService) OAuthCallback(c *fiber.Ctx) error {
    provider := c.Params("provider")
    
    config, ok := s.oauthConfigs[provider]
    if !ok {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid provider")
    }
    
    // Verify state
    state := c.Query("state")
    ctx := context.Background()
    
    storedProvider, err := s.redis.Get(ctx, fmt.Sprintf("oauth:state:%s", state)).Result()
    if err != nil || storedProvider != provider {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid state")
    }
    
    // Delete state
    s.redis.Del(ctx, fmt.Sprintf("oauth:state:%s", state))
    
    // Exchange code for token
    code := c.Query("code")
    token, err := config.Exchange(ctx, code)
    if err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Failed to exchange code")
    }
    
    // Get user info
    userInfo, err := s.getOAuthUserInfo(provider, token)
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user info")
    }
    
    // Find or create user
    var oauthAccount OAuthAccount
    if err := s.db.Where("provider = ? AND provider_id = ?", provider, userInfo.ID).First(&oauthAccount).Error; err != nil {
        // Create new user
        user := &User{
            ID:       uuid.New(),
            Email:    userInfo.Email,
            Username: userInfo.Email,
            PasswordHash: "oauth", // Placeholder
            Role:     "user",
            Status:   "active",
        }
        
        if err := s.db.Create(user).Error; err != nil {
            return fiber.NewError(fiber.StatusInternalServerError, "Failed to create user")
        }
        
        // Create OAuth account
        oauthAccount = OAuthAccount{
            ID:          uuid.New(),
            UserID:      user.ID,
            Provider:    provider,
            ProviderID:  userInfo.ID,
            AccessToken: token.AccessToken,
            Email:       userInfo.Email,
        }
        
        if err := s.db.Create(&oauthAccount).Error; err != nil {
            return fiber.NewError(fiber.StatusInternalServerError, "Failed to create OAuth account")
        }
    } else {
        // Update access token
        oauthAccount.AccessToken = token.AccessToken
        s.db.Save(&oauthAccount)
    }
    
    // Get user
    var user User
    if err := s.db.First(&user, oauthAccount.UserID).Error; err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to get user")
    }
    
    // Generate tokens
    accessToken, refreshToken, err := s.generateTokens(&user)
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to generate tokens")
    }
    
    // Create session
    session := &Session{
        ID:           uuid.New(),
        UserID:       user.ID,
        RefreshToken: refreshToken,
        UserAgent:    c.Get("User-Agent"),
        IP:           c.IP(),
        ExpiresAt:    time.Now().Add(s.refreshExpiry),
        CreatedAt:    time.Now(),
        LastUsedAt:   time.Now(),
    }
    
    if err := s.db.Create(session).Error; err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to create session")
    }
    
    // Redirect to frontend with tokens
    redirectURL := fmt.Sprintf("%s/auth/callback?access_token=%s&refresh_token=%s", 
        os.Getenv("FRONTEND_URL"), accessToken, refreshToken)
    
    return c.Redirect(redirectURL)
}

// WebAuthn handlers
func (s *AuthService) BeginWebAuthnRegistration(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    
    var user User
    if err := s.db.First(&user, userID).Error; err != nil {
        return fiber.NewError(fiber.StatusNotFound, "User not found")
    }
    
    webAuthnUser := &WebAuthnUser{
        user: &user,
    }
    
    options, sessionData, err := s.webAuthn.BeginRegistration(webAuthnUser)
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to begin registration")
    }
    
    // Store session data in Redis
    ctx := context.Background()
    sessionJSON, _ := json.Marshal(sessionData)
    if err := s.redis.Set(ctx, fmt.Sprintf("webauthn:reg:%s", user.ID), sessionJSON, 5*time.Minute).Err(); err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to store session")
    }
    
    return c.JSON(options)
}

func (s *AuthService) FinishWebAuthnRegistration(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    
    var user User
    if err := s.db.First(&user, userID).Error; err != nil {
        return fiber.NewError(fiber.StatusNotFound, "User not found")
    }
    
    // Get session data
    ctx := context.Background()
    sessionJSON, err := s.redis.Get(ctx, fmt.Sprintf("webauthn:reg:%s", user.ID)).Result()
    if err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Registration session expired")
    }
    
    var sessionData webauthn.SessionData
    if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to parse session")
    }
    
    webAuthnUser := &WebAuthnUser{
        user: &user,
    }
    
    credential, err := s.webAuthn.FinishRegistration(webAuthnUser, sessionData, c.Body())
    if err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Failed to finish registration")
    }
    
    // Save credential
    cred := &WebAuthnCred{
        ID:              uuid.New(),
        UserID:          user.ID,
        CredentialID:    credential.ID,
        PublicKey:       credential.PublicKey,
        AttestationType: string(credential.AttestationType),
        Transport:       credential.Transport,
        Flags:           credential.Flags,
        Authenticator:   credential.Authenticator,
    }
    
    if err := s.db.Create(cred).Error; err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, "Failed to save credential")
    }
    
    // Delete session
    s.redis.Del(ctx, fmt.Sprintf("webauthn:reg:%s", user.ID))
    
    return c.JSON(fiber.Map{
        "message": "WebAuthn device registered successfully",
    })
}

// Middleware
func (s *AuthService) Middleware() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Get token from header
        authHeader := c.Get("Authorization")
        if authHeader == "" {
            return fiber.NewError(fiber.StatusUnauthorized, "Missing authorization header")
        }
        
        // Parse token
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        
        // Verify token
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
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
        
        userIDStr, ok := claims["sub"].(string)
        if !ok {
            return fiber.NewError(fiber.StatusUnauthorized, "Invalid user ID in token")
        }
        
        userID, err := uuid.Parse(userIDStr)
        if err != nil {
            return fiber.NewError(fiber.StatusUnauthorized, "Invalid user ID format")
        }
        
        // Check if user exists and is active
        var user User
        if err := s.db.First(&user, userID).Error; err != nil {
            return fiber.NewError(fiber.StatusUnauthorized, "User not found")
        }
        
        if user.Status != "active" {
            return fiber.NewError(fiber.StatusForbidden, "Account is not active")
        }
        
        // Add user to context
        c.Locals("userID", userID)
        c.Locals("userRole", user.Role)
        
        return c.Next()
    }
}

// RequireRole middleware
func (s *AuthService) RequireRole(roles ...string) fiber.Handler {
    return func(c *fiber.Ctx) error {
        userRole := c.Locals("userRole").(string)
        
        for _, role := range roles {
            if userRole == role {
                return c.Next()
            }
        }
        
        return fiber.NewError(fiber.StatusForbidden, "Insufficient permissions")
    }
}

// Helper functions
func (s *AuthService) generateTokens(user *User) (string, string, error) {
    // Access token
    accessClaims := jwt.MapClaims{
        "sub":  user.ID.String(),
        "role": user.Role,
        "exp":  time.Now().Add(s.tokenExpiry).Unix(),
        "iat":  time.Now().Unix(),
    }
    
    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    accessTokenString, err := accessToken.SignedString(s.jwtSecret)
    if err != nil {
        return "", "", err
    }
    
    // Refresh token
    refreshToken := uuid.New().String()
    
    return accessTokenString, refreshToken, nil
}

func (s *AuthService) generateBackupCodes(count int) []string {
    codes := make([]string, count)
    for i := 0; i < count; i++ {
        codes[i] = fmt.Sprintf("%06d-%06d", randInt(0, 999999), randInt(0, 999999))
    }
    return codes
}

func (s *AuthService) hashBackupCodes(codes []string) []string {
    hashed := make([]string, len(codes))
    for i, code := range codes {
        hash, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
        hashed[i] = string(hash)
    }
    return hashed
}

func (s *AuthService) checkBackupCode(user *User, code string) bool {
    for i, hashedCode := range user.TwoFactorAuth.BackupCodes {
        if err := bcrypt.CompareHashAndPassword([]byte(hashedCode), []byte(code)); err == nil {
            // Remove used code
            user.TwoFactorAuth.BackupCodes = append(
                user.TwoFactorAuth.BackupCodes[:i],
                user.TwoFactorAuth.BackupCodes[i+1:]...,
            )
            s.db.Save(user.TwoFactorAuth)
            return true
        }
    }
    return false
}

func (s *AuthService) checkBruteForce(c *fiber.Ctx, userID uuid.UUID) bool {
    ctx := context.Background()
    key := fmt.Sprintf("failed_login:%s:%s", userID, c.IP())
    
    count, _ := s.redis.Get(ctx, key).Int()
    return count >= 5
}

func (s *AuthService) logFailedLogin(c *fiber.Ctx, username string) {
    ctx := context.Background()
    key := fmt.Sprintf("failed_login:%s:%s", username, c.IP())
    
    s.redis.Incr(ctx, key)
    s.redis.Expire(ctx, key, 15*time.Minute)
}

func (s *AuthService) clearFailedAttempts(c *fiber.Ctx, userID uuid.UUID) {
    ctx := context.Background()
    key := fmt.Sprintf("failed_login:%s:%s", userID, c.IP())
    
    s.redis.Del(ctx, key)
}

func (s *AuthService) logSuccessfulLogin(user *User, c *fiber.Ctx) {
    log.Printf("Successful login: user=%s ip=%s", user.Username, c.IP())
    
    // Send notification if enabled
    // TODO: Implement notification
}

// WebAuthnUser implements webauthn.User interface
type WebAuthnUser struct {
    user *User
}

func (u *WebAuthnUser) WebAuthnID() []byte {
    return u.user.ID[:]
}

func (u *WebAuthnUser) WebAuthnName() string {
    return u.user.Username
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
    return u.user.Email
}

func (u *WebAuthnUser) WebAuthnIcon() string {
    return ""
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
    var creds []WebAuthnCred
    db.Where("user_id = ?", u.user.ID).Find(&creds)
    
    credentials := make([]webauthn.Credential, len(creds))
    for i, cred := range creds {
        credentials[i] = webauthn.Credential{
            ID:              cred.CredentialID,
            PublicKey:       cred.PublicKey,
            AttestationType: cred.AttestationType,
            Transport:       cred.Transport,
            Flags:           cred.Flags,
            Authenticator:   cred.Authenticator,
        }
    }
    
    return credentials
}

// Main function
func main() {
    // Load config
    config := loadConfig()
    
    // Connect to database
    db, err := gorm.Open(postgres.Open(config.Database.URL), &gorm.Config{})
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    
    // Auto migrate
    db.AutoMigrate(&User{}, &TwoFactorAuth{}, &WebAuthnCred{}, &OAuthAccount{}, &Session{})
    
    // Connect to Redis
    redis := redis.NewClient(&redis.Options{
        Addr:     config.Redis.Addr,
        Password: config.Redis.Password,
        DB:       config.Redis.DB,
    })
    
    // Create auth service
    authService, err := NewAuthService(db, redis, config)
    if err != nil {
        log.Fatal("Failed to create auth service:", err)
    }
    
    // Create fiber app
    app := fiber.New(fiber.Config{
        AppName: "VortexPanel Auth Service",
        ErrorHandler: func(c *fiber.Ctx, err error) error {
            code := fiber.StatusInternalServerError
            message := "Internal Server Error"
            
            if e, ok := err.(*fiber.Error); ok {
                code = e.Code
                message = e.Message
            }
            
            return c.Status(code).JSON(fiber.Map{
                "error": message,
            })
        },
    })
    
    // Middleware
    app.Use(recover.New())
    app.Use(logger.New())
    app.Use(cors.New(cors.Config{
        AllowOrigins:     config.CORS.AllowedOrigins,
        AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders:     "Origin,Content-Type,Accept,Authorization",
        AllowCredentials: true,
    }))
    
    // Routes
    api := app.Group("/api/v1")
    
    // Public routes
    api.Post("/auth/login", authService.Login)
    api.Post("/auth/register", authService.Register)
    api.Post("/auth/refresh", authService.RefreshToken)
    api.Post("/auth/forgot-password", authService.ForgotPassword)
    api.Post("/auth/reset-password", authService.ResetPassword)
    
    // OAuth routes
    api.Get("/auth/oauth/:provider", authService.OAuthLogin)
    api.Get("/auth/oauth/:provider/callback", authService.OAuthCallback)
    
    // WebAuthn routes
    api.Post("/auth/webauthn/login/begin", authService.BeginWebAuthnLogin)
    api.Post("/auth/webauthn/login/finish", authService.FinishWebAuthnLogin)
    
    // Protected routes
    protected := api.Use(authService.Middleware())
    
    protected.Post("/auth/logout", authService.Logout)
    protected.Get("/auth/me", authService.GetMe)
    protected.Put("/auth/me", authService.UpdateMe)
    protected.Put("/auth/password", authService.ChangePassword)
    
    // 2FA routes
    protected.Post("/auth/2fa/setup", authService.Setup2FA)
    protected.Post("/auth/2fa/verify", authService.Verify2FA)
    protected.Delete("/auth/2fa", authService.Disable2FA)
    
    // WebAuthn routes
    protected.Post("/auth/webauthn/register/begin", authService.BeginWebAuthnRegistration)
    protected.Post("/auth/webauthn/register/finish", authService.FinishWebAuthnRegistration)
    protected.Delete("/auth/webauthn/:id", authService.DeleteWebAuthnCredential)
    
    // Session management
    protected.Get("/auth/sessions", authService.GetSessions)
    protected.Delete("/auth/sessions/:id", authService.RevokeSession)
    
    // Admin routes
    admin := protected.Use(authService.RequireRole("admin"))
    admin.Get("/auth/users", authService.ListUsers)
    admin.Get("/auth/users/:id", authService.GetUser)
    admin.Put("/auth/users/:id", authService.UpdateUser)
    admin.Delete("/auth/users/:id", authService.DeleteUser)
    
    // Health check
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"status": "ok"})
    })
    
    // Start server
    go func() {
        if err := app.Listen(":8080"); err != nil {
            log.Fatal("Failed to start server:", err)
        }
    }()
    
    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    log.Println("Shutting down server...")
    
    if err := app.Shutdown(); err != nil {
        log.Fatal("Server shutdown error:", err)
    }
    
    log.Println("Server shutdown complete")
}