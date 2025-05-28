// services/notification/main.go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    firebase "firebase.google.com/go/v4"
    "firebase.google.com/go/v4/messaging"
    "github.com/gofiber/fiber/v2"
    "github.com/google/uuid"
    "github.com/nikoksr/notify"
    "github.com/nikoksr/notify/service/discord"
    "github.com/nikoksr/notify/service/mail"
    "github.com/nikoksr/notify/service/slack"
    "github.com/nikoksr/notify/service/telegram"
    "github.com/rabbitmq/amqp091-go"
    "github.com/redis/go-redis/v9"
    "github.com/vortexpanel/shared/models"
    "google.golang.org/api/option"
    "gopkg.in/gomail.v2"
    "gorm.io/gorm"
)

// NotificationService handles all notifications
type NotificationService struct {
    db              *gorm.DB
    redis           *redis.Client
    rabbit          *amqp091.Connection
    notifier        *notify.Notify
    emailDialer     *gomail.Dialer
    telegramBot     *telegram.Telegram
    firebaseApp     *firebase.App
    fcmClient       *messaging.Client
    templates       map[string]*NotificationTemplate
}

// Models
type Notification struct {
    ID         uuid.UUID           `gorm:"type:uuid;primary_key" json:"id"`
    UserID     uuid.UUID           `gorm:"type:uuid;not null" json:"user_id"`
    Type       NotificationType    `gorm:"not null" json:"type"`
    Channel    NotificationChannel `gorm:"not null" json:"channel"`
    Title      string              `gorm:"not null" json:"title"`
    Message    string              `gorm:"not null" json:"message"`
    Data       map[string]string   `gorm:"type:jsonb" json:"data,omitempty"`
    Priority   Priority            `gorm:"default:'normal'" json:"priority"`
    Status     NotificationStatus  `gorm:"default:'pending'" json:"status"`
    Read       bool                `gorm:"default:false" json:"read"`
    ReadAt     *time.Time          `json:"read_at,omitempty"`
    Error      string              `json:"error,omitempty"`
    RetryCount int                 `gorm:"default:0" json:"retry_count"`
    CreatedAt  time.Time           `json:"created_at"`
    SentAt     *time.Time          `json:"sent_at,omitempty"`
}

type NotificationType string

const (
    TypeInfo          NotificationType = "info"
    TypeWarning       NotificationType = "warning"
    TypeError         NotificationType = "error"
    TypeSuccess       NotificationType = "success"
    TypeTrafficLimit  NotificationType = "traffic_limit"
    TypeExpiryWarning NotificationType = "expiry_warning"
    TypePaymentDue    NotificationType = "payment_due"
    TypeSystemUpdate  NotificationType = "system_update"
    TypeSecurityAlert NotificationType = "security_alert"
    TypeNewLogin      NotificationType = "new_login"
)

type NotificationChannel string

const (
    ChannelEmail    NotificationChannel = "email"
    ChannelPush     NotificationChannel = "push"
    ChannelTelegram NotificationChannel = "telegram"
    ChannelSMS      NotificationChannel = "sms"
    ChannelDiscord  NotificationChannel = "discord"
    ChannelSlack    NotificationChannel = "slack"
    ChannelWebhook  NotificationChannel = "webhook"
)

type NotificationStatus string

const (
    StatusPending   NotificationStatus = "pending"
    StatusSent      NotificationStatus = "sent"
    StatusFailed    NotificationStatus = "failed"
    StatusCancelled NotificationStatus = "cancelled"
)

type Priority string

const (
    PriorityLow    Priority = "low"
    PriorityNormal Priority = "normal"
    PriorityHigh   Priority = "high"
    PriorityUrgent Priority = "urgent"
)

type NotificationTemplate struct {
    ID          uuid.UUID               `gorm:"type:uuid;primary_key" json:"id"`
    Name        string                  `gorm:"uniqueIndex;not null" json:"name"`
    Type        NotificationType        `gorm:"not null" json:"type"`
    Subject     string                  `json:"subject"`
    HTMLBody    string                  `json:"html_body"`
    TextBody    string                  `json:"text_body"`
    Variables   []string                `gorm:"type:text[]" json:"variables"`
    Locales     map[string]LocaleTemplate `gorm:"type:jsonb" json:"locales"`
    Active      bool                    `gorm:"default:true" json:"active"`
    CreatedAt   time.Time               `json:"created_at"`
    UpdatedAt   time.Time               `json:"updated_at"`
}

type LocaleTemplate struct {
    Subject  string `json:"subject"`
    HTMLBody string `json:"html_body"`
    TextBody string `json:"text_body"`
}

type UserPreferences struct {
    ID               uuid.UUID                  `gorm:"type:uuid;primary_key" json:"id"`
    UserID           uuid.UUID                  `gorm:"type:uuid;uniqueIndex;not null" json:"user_id"`
    EmailEnabled     bool                       `gorm:"default:true" json:"email_enabled"`
    PushEnabled      bool                       `gorm:"default:true" json:"push_enabled"`
    TelegramEnabled  bool                       `gorm:"default:false" json:"telegram_enabled"`
    TelegramChatID   string                     `json:"telegram_chat_id,omitempty"`
    DiscordEnabled   bool                       `gorm:"default:false" json:"discord_enabled"`
    DiscordWebhook   string                     `json:"discord_webhook,omitempty"`
    PreferredChannel NotificationChannel        `gorm:"default:'email'" json:"preferred_channel"`
    EventPrefs       map[string]bool            `gorm:"type:jsonb" json:"event_prefs"`
    QuietHours       *QuietHours                `gorm:"type:jsonb" json:"quiet_hours,omitempty"`
    CreatedAt        time.Time                  `json:"created_at"`
    UpdatedAt        time.Time                  `json:"updated_at"`
}

type QuietHours struct {
    Enabled   bool   `json:"enabled"`
    StartTime string `json:"start_time"` // Format: "22:00"
    EndTime   string `json:"end_time"`   // Format: "08:00"
    Timezone  string `json:"timezone"`
}

type PushToken struct {
    ID        uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
    UserID    uuid.UUID  `gorm:"type:uuid;not null" json:"user_id"`
    Token     string     `gorm:"not null" json:"token"`
    Platform  string     `gorm:"not null" json:"platform"` // ios, android, web
    DeviceID  string     `json:"device_id"`
    Active    bool       `gorm:"default:true" json:"active"`
    CreatedAt time.Time  `json:"created_at"`
    UpdatedAt time.Time  `json:"updated_at"`
}

// NewNotificationService creates a new notification service
func NewNotificationService(db *gorm.DB, redis *redis.Client, rabbit *amqp091.Connection, config *Config) (*NotificationService, error) {
    // Initialize email
    emailDialer := gomail.NewDialer(config.SMTP.Host, config.SMTP.Port, config.SMTP.User, config.SMTP.Pass)

    // Initialize notifier
    notifier := notify.New()

    // Email service
    mailService := mail.New(config.SMTP.User, config.SMTP.Host+":"+fmt.Sprint(config.SMTP.Port))
    mailService.AuthenticateSMTP("", config.SMTP.User, config.SMTP.Pass, config.SMTP.Host)
    notifier.UseServices(mailService)

    // Telegram service
    var telegramBot *telegram.Telegram
    if config.Telegram.BotToken != "" {
        telegramBot, _ = telegram.New(config.Telegram.BotToken)
        notifier.UseServices(telegramBot)
    }

    // Discord service
    if config.Discord.WebhookURL != "" {
        discordService := discord.New()
        discordService.AddReceivers(config.Discord.WebhookURL)
        notifier.UseServices(discordService)
    }

    // Slack service
    if config.Slack.WebhookURL != "" {
        slackService := slack.New(config.Slack.WebhookURL)
        notifier.UseServices(slackService)
    }

    // Initialize Firebase
    var firebaseApp *firebase.App
    var fcmClient *messaging.Client
    if config.Firebase.CredentialsPath != "" {
        opt := option.WithCredentialsFile(config.Firebase.CredentialsPath)
        app, err := firebase.NewApp(context.Background(), nil, opt)
        if err != nil {
            log.Printf("Failed to initialize Firebase: %v", err)
        } else {
            firebaseApp = app
            fcmClient, _ = app.Messaging(context.Background())
        }
    }

    service := &NotificationService{
        db:           db,
        redis:        redis,
        rabbit:       rabbit,
        notifier:     notifier,
        emailDialer:  emailDialer,
        telegramBot:  telegramBot,
        firebaseApp:  firebaseApp,
        fcmClient:    fcmClient,
        templates:    make(map[string]*NotificationTemplate),
    }

    // Load templates
    service.loadTemplates()

    // Start workers
    go service.startWorkers()

    return service, nil
}

// Send sends a notification
func (s *NotificationService) Send(ctx context.Context, notification *Notification) error {
    notification.ID = uuid.New()
    notification.CreatedAt = time.Now()
    notification.Status = StatusPending

    // Get user preferences
    prefs, err := s.getUserPreferences(ctx, notification.UserID)
    if err != nil {
        return fmt.Errorf("failed to get user preferences: %w", err)
    }

    // Check if notification type is enabled
    if eventEnabled, ok := prefs.EventPrefs[string(notification.Type)]; ok && !eventEnabled {
        notification.Status = StatusCancelled
        s.db.Create(notification)
        return nil
    }

    // Check quiet hours
    if s.isInQuietHours(prefs) && notification.Priority != PriorityUrgent {
        // Schedule for later
        return s.scheduleNotification(ctx, notification, s.getNextActiveTime(prefs))
    }

    // Override channel based on preferences if not specified
    if notification.Channel == "" {
        notification.Channel = prefs.PreferredChannel
    }

    // Save notification
    if err := s.db.Create(notification).Error; err != nil {
        return fmt.Errorf("failed to save notification: %w", err)
    }

    // Send based on priority
    if notification.Priority == PriorityUrgent {
        return s.sendImmediate(ctx, notification, prefs)
    }

    // Queue for processing
    return s.queueNotification(ctx, notification)
}

// sendImmediate sends notification immediately
func (s *NotificationService) sendImmediate(ctx context.Context, notification *Notification, prefs *UserPreferences) error {
    var err error

    switch notification.Channel {
    case ChannelEmail:
        err = s.sendEmail(ctx, notification)
    case ChannelPush:
        err = s.sendPush(ctx, notification)
    case ChannelTelegram:
        err = s.sendTelegram(ctx, notification, prefs.TelegramChatID)
    case ChannelDiscord:
        err = s.sendDiscord(ctx, notification, prefs.DiscordWebhook)
    case ChannelWebhook:
        err = s.sendWebhook(ctx, notification)
    default:
        err = fmt.Errorf("unsupported channel: %s", notification.Channel)
    }

    if err != nil {
        notification.Status = StatusFailed
        notification.Error = err.Error()
        notification.RetryCount++
    } else {
        notification.Status = StatusSent
        now := time.Now()
        notification.SentAt = &now
    }

    s.db.Save(notification)
    return err
}

// sendEmail sends email notification
func (s *NotificationService) sendEmail(ctx context.Context, notification *Notification) error {
    // Get user email
    var user models.User
    if err := s.db.First(&user, notification.UserID).Error; err != nil {
        return fmt.Errorf("user not found: %w", err)
    }

    // Get template
    template, exists := s.templates[string(notification.Type)]
    if !exists {
        // Use default template
        template = s.getDefaultTemplate(notification.Type)
    }

    // Parse template
    subject := s.parseTemplate(template.Subject, notification.Data)
    htmlBody := s.parseTemplate(template.HTMLBody, notification.Data)
    textBody := s.parseTemplate(template.TextBody, notification.Data)

    // Create message
    m := gomail.NewMessage()
    m.SetHeader("From", s.emailDialer.Username)
    m.SetHeader("To", user.Email)
    m.SetHeader("Subject", subject)
    m.SetBody("text/plain", textBody)
    m.AddAlternative("text/html", htmlBody)

    // Add headers
    m.SetHeader("X-Notification-ID", notification.ID.String())
    m.SetHeader("X-Notification-Type", string(notification.Type))

    // Send
    if err := s.emailDialer.DialAndSend(m); err != nil {
        return fmt.Errorf("failed to send email: %w", err)
    }

    return nil
}

// sendPush sends push notification
func (s *NotificationService) sendPush(ctx context.Context, notification *Notification) error {
    if s.fcmClient == nil {
        return fmt.Errorf("Firebase not configured")
    }

    // Get user push tokens
    var tokens []PushToken
    if err := s.db.Where("user_id = ? AND active = ?", notification.UserID, true).Find(&tokens).Error; err != nil {
        return fmt.Errorf("failed to get push tokens: %w", err)
    }

    if len(tokens) == 0 {
        return fmt.Errorf("no active push tokens found")
    }

    // Create message
    message := &messaging.MulticastMessage{
        Notification: &messaging.Notification{
            Title: notification.Title,
            Body:  notification.Message,
        },
        Data: notification.Data,
        Android: &messaging.AndroidConfig{
            Priority: "high",
            Notification: &messaging.AndroidNotification{
                Icon:  "ic_notification",
                Color: "#6366F1",
            },
        },
        APNS: &messaging.APNSConfig{
            Headers: map[string]string{
                "apns-priority": "10",
            },
            Payload: &messaging.APNSPayload{
                Aps: &messaging.Aps{
                    Alert: &messaging.ApsAlert{
                        Title: notification.Title,
                        Body:  notification.Message,
                    },
                    Badge: &[]int{1}[0],
                    Sound: "default",
                },
            },
        },
        Tokens: s.getTokenStrings(tokens),
    }

    // Send multicast
    response, err := s.fcmClient.SendMulticast(ctx, message)
    if err != nil {
        return fmt.Errorf("failed to send push notification: %w", err)
    }

    // Handle failed tokens
    if response.FailureCount > 0 {
        for i, result := range response.Responses {
            if !result.Success {
                log.Printf("Failed to send to token %s: %v", tokens[i].Token, result.Error)
                // Mark token as inactive
                tokens[i].Active = false
                s.db.Save(&tokens[i])
            }
        }
    }

    return nil
}

// sendTelegram sends Telegram notification
func (s *NotificationService) sendTelegram(ctx context.Context, notification *Notification, chatID string) error {
    if s.telegramBot == nil {
        return fmt.Errorf("Telegram not configured")
    }

    if chatID == "" {
        return fmt.Errorf("Telegram chat ID not set")
    }

    // Format message
    message := fmt.Sprintf("*%s*\n\n%s", 
        s.escapeMarkdown(notification.Title),
        s.escapeMarkdown(notification.Message))

    // Add data fields
    if len(notification.Data) > 0 {
        message += "\n\n"
        for key, value := range notification.Data {
            message += fmt.Sprintf("_%s:_ %s\n", 
                s.escapeMarkdown(key),
                s.escapeMarkdown(value))
        }
    }

    s.telegramBot.AddReceivers(chatID)
    return s.telegramBot.Send(ctx, "", message)
}

// queueNotification queues notification for processing
func (s *NotificationService) queueNotification(ctx context.Context, notification *Notification) error {
    ch, err := s.rabbit.Channel()
    if err != nil {
        return fmt.Errorf("failed to open channel: %w", err)
    }
    defer ch.Close()

    // Declare queue
    queue, err := ch.QueueDeclare(
        "notifications", // name
        true,           // durable
        false,          // delete when unused
        false,          // exclusive
        false,          // no-wait
        nil,            // arguments
    )
    if err != nil {
        return fmt.Errorf("failed to declare queue: %w", err)
    }

    body, err := json.Marshal(notification)
    if err != nil {
        return fmt.Errorf("failed to marshal notification: %w", err)
    }

    // Set priority
    priority := s.getPriorityValue(notification.Priority)

    err = ch.Publish(
        "",         // exchange
        queue.Name, // routing key
        false,      // mandatory
        false,      // immediate
        amqp091.Publishing{
            ContentType: "application/json",
            Body:        body,
            Priority:    priority,
        })

    if err != nil {
        return fmt.Errorf("failed to publish message: %w", err)
    }

    return nil
}

// startWorkers starts notification workers
func (s *NotificationService) startWorkers() {
    // Start multiple workers
    workerCount := 5
    for i := 0; i < workerCount; i++ {
        go s.worker(i)
    }

    // Start scheduled notification processor
    go s.processScheduledNotifications()

    // Start retry processor
    go s.processFailedNotifications()
}

// worker processes notifications from queue
func (s *NotificationService) worker(id int) {
    ch, err := s.rabbit.Channel()
    if err != nil {
        log.Printf("Worker %d: Failed to open channel: %v", id, err)
        return
    }
    defer ch.Close()

    // Set QoS
    ch.Qos(1, 0, false)

    // Declare queue
    queue, err := ch.QueueDeclare(
        "notifications", // name
        true,           // durable
        false,          // delete when unused
        false,          // exclusive
        false,          // no-wait
        nil,            // arguments
    )
    if err != nil {
        log.Printf("Worker %d: Failed to declare queue: %v", id, err)
        return
    }

    msgs, err := ch.Consume(
        queue.Name, // queue
        "",         // consumer
        false,      // auto-ack
        false,      // exclusive
        false,      // no-local
        false,      // no-wait
        nil,        // args
    )
    if err != nil {
        log.Printf("Worker %d: Failed to register consumer: %v", id, err)
        return
    }

    log.Printf("Worker %d: Started", id)

    for msg := range msgs {
        var notification Notification
        if err := json.Unmarshal(msg.Body, &notification); err != nil {
            log.Printf("Worker %d: Failed to unmarshal notification: %v", id, err)
            msg.Nack(false, false)
            continue
        }

        // Process notification
        ctx := context.Background()
        
        // Get user preferences
        prefs, err := s.getUserPreferences(ctx, notification.UserID)
        if err != nil {
            log.Printf("Worker %d: Failed to get user preferences: %v", id, err)
            msg.Nack(false, true)
            continue
        }

        // Send notification
        if err := s.sendImmediate(ctx, &notification, prefs); err != nil {
            log.Printf("Worker %d: Failed to send notification: %v", id, err)
            
            // Check retry count
            if notification.RetryCount < 3 {
                msg.Nack(false, true) // Requeue
            } else {
                msg.Ack(false) // Give up
            }
        } else {
            msg.Ack(false)
        }
    }
}

// processScheduledNotifications processes scheduled notifications
func (s *NotificationService) processScheduledNotifications() {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        ctx := context.Background()
        
        // Get scheduled notifications
        var notifications []Notification
        s.db.Where("status = ? AND scheduled_at <= ?", StatusPending, time.Now()).
            Limit(100).
            Find(&notifications)

        for _, notification := range notifications {
            if err := s.queueNotification(ctx, &notification); err != nil {
                log.Printf("Failed to queue scheduled notification: %v", err)
            }
        }
    }
}

// processFailedNotifications retries failed notifications
func (s *NotificationService) processFailedNotifications() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        ctx := context.Background()
        
        // Get failed notifications for retry
        var notifications []Notification
        s.db.Where("status = ? AND retry_count < ? AND created_at > ?", 
            StatusFailed, 3, time.Now().Add(-24*time.Hour)).
            Limit(50).
            Find(&notifications)

        for _, notification := range notifications {
            // Exponential backoff
            waitTime := time.Duration(notification.RetryCount*notification.RetryCount) * time.Minute
            if time.Since(notification.CreatedAt) < waitTime {
                continue
            }

            if err := s.queueNotification(ctx, &notification); err != nil {
                log.Printf("Failed to requeue notification: %v", err)
            }
        }
    }
}

// Helper methods
func (s *NotificationService) getUserPreferences(ctx context.Context, userID uuid.UUID) (*UserPreferences, error) {
    var prefs UserPreferences
    
    err := s.db.Where("user_id = ?", userID).First(&prefs).Error
    if err == gorm.ErrRecordNotFound {
        // Create default preferences
        prefs = UserPreferences{
            ID:               uuid.New(),
            UserID:           userID,
            EmailEnabled:     true,
            PushEnabled:      true,
            PreferredChannel: ChannelEmail,
            EventPrefs:       s.getDefaultEventPrefs(),
        }
        s.db.Create(&prefs)
    } else if err != nil {
        return nil, err
    }

    return &prefs, nil
}

func (s *NotificationService) getDefaultEventPrefs() map[string]bool {
    return map[string]bool{
        string(TypeInfo):          true,
        string(TypeWarning):       true,
        string(TypeError):         true,
        string(TypeSuccess):       true,
        string(TypeTrafficLimit):  true,
        string(TypeExpiryWarning): true,
        string(TypePaymentDue):    true,
        string(TypeSystemUpdate):  false,
        string(TypeSecurityAlert): true,
        string(TypeNewLogin):      true,
    }
}

func (s *NotificationService) isInQuietHours(prefs *UserPreferences) bool {
    if prefs.QuietHours == nil || !prefs.QuietHours.Enabled {
        return false
    }

    loc, err := time.LoadLocation(prefs.QuietHours.Timezone)
    if err != nil {
        loc = time.UTC
    }

    now := time.Now().In(loc)
    startTime, _ := time.Parse("15:04", prefs.QuietHours.StartTime)
    endTime, _ := time.Parse("15:04", prefs.QuietHours.EndTime)

    start := time.Date(now.Year(), now.Month(), now.Day(), 
        startTime.Hour(), startTime.Minute(), 0, 0, loc)
    end := time.Date(now.Year(), now.Month(), now.Day(), 
        endTime.Hour(), endTime.Minute(), 0, 0, loc)

    if end.Before(start) {
        // Spans midnight
        return now.After(start) || now.Before(end)
    }

    return now.After(start) && now.Before(end)
}

func (s *NotificationService) loadTemplates() {
    var templates []NotificationTemplate
    s.db.Where("active = ?", true).Find(&templates)

    for _, template := range templates {
        s.templates[template.Name] = &template
    }

    // Load default templates if none exist
    if len(s.templates) == 0 {
        s.loadDefaultTemplates()
    }
}

func (s *NotificationService) getDefaultTemplate(notifType NotificationType) *NotificationTemplate {
    return &NotificationTemplate{
        Name:     string(notifType),
        Type:     notifType,
        Subject:  "{{.title}}",
        HTMLBody: "<h2>{{.title}}</h2><p>{{.message}}</p>",
        TextBody: "{{.title}}\n\n{{.message}}",
    }
}

func (s *NotificationService) parseTemplate(template string, data map[string]string) string {
    result := template
    for key, value := range data {
        result = strings.ReplaceAll(result, "{{."+key+"}}", value)
    }
    return result
}

func (s *NotificationService) escapeMarkdown(text string) string {
    replacer := strings.NewReplacer(
        "_", "\\_",
        "*", "\\*",
        "[", "\\[",
        "]", "\\]",
        "(", "\\(",
        ")", "\\)",
        "~", "\\~",
        "`", "\\`",
        ">", "\\>",
        "#", "\\#",
        "+", "\\+",
        "-", "\\-",
        "=", "\\=",
        "|", "\\|",
        "{", "\\{",
        "}", "\\}",
        ".", "\\.",
        "!", "\\!",
    )
    return replacer.Replace(text)
}

func (s *NotificationService) getPriorityValue(priority Priority) uint8 {
    switch priority {
    case PriorityUrgent:
        return 9
    case PriorityHigh:
        return 7
    case PriorityNormal:
        return 5
    case PriorityLow:
        return 3
    default:
        return 5
    }
}

func (s *NotificationService) getTokenStrings(tokens []PushToken) []string {
    result := make([]string, len(tokens))
    for i, token := range tokens {
        result[i] = token.Token
    }
    return result
}

// API Handlers
func (s *NotificationService) HandleSendNotification(c *fiber.Ctx) error {
    var req struct {
        UserID   uuid.UUID           `json:"user_id" validate:"required"`
        Type     NotificationType    `json:"type" validate:"required"`
        Channel  NotificationChannel `json:"channel"`
        Title    string              `json:"title" validate:"required"`
        Message  string              `json:"message" validate:"required"`
        Data     map[string]string   `json:"data"`
        Priority Priority            `json:"priority"`
    }

    if err := c.BodyParser(&req); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request")
    }

    notification := &Notification{
        UserID:   req.UserID,
        Type:     req.Type,
        Channel:  req.Channel,
        Title:    req.Title,
        Message:  req.Message,
        Data:     req.Data,
        Priority: req.Priority,
    }

    if notification.Priority == "" {
        notification.Priority = PriorityNormal
    }

    if err := s.Send(c.Context(), notification); err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.Status(fiber.StatusCreated).JSON(notification)
}

func (s *NotificationService) HandleGetNotifications(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    
    page := c.QueryInt("page", 1)
    limit := c.QueryInt("limit", 20)
    offset := (page - 1) * limit

    var notifications []Notification
    var total int64

    query := s.db.Model(&Notification{}).Where("user_id = ?", userID)
    
    // Apply filters
    if notifType := c.Query("type"); notifType != "" {
        query = query.Where("type = ?", notifType)
    }
    
    if status := c.Query("status"); status != "" {
        query = query.Where("status = ?", status)
    }
    
    if unreadOnly := c.QueryBool("unread", false); unreadOnly {
        query = query.Where("read = ?", false)
    }

    query.Count(&total)
    query.Order("created_at DESC").Offset(offset).Limit(limit).Find(&notifications)

    return c.JSON(fiber.Map{
        "notifications": notifications,
        "total":         total,
        "page":          page,
        "limit":         limit,
        "unread_count":  s.getUnreadCount(userID),
    })
}

func (s *NotificationService) HandleMarkAsRead(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    notificationID, err := uuid.Parse(c.Params("id"))
    if err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid notification ID")
    }

    now := time.Now()
    result := s.db.Model(&Notification{}).
        Where("id = ? AND user_id = ?", notificationID, userID).
        Updates(map[string]interface{}{
            "read":    true,
            "read_at": now,
        })

    if result.RowsAffected == 0 {
        return fiber.NewError(fiber.StatusNotFound, "Notification not found")
    }

    return c.JSON(fiber.Map{
        "message": "Notification marked as read",
    })
}

func (s *NotificationService) HandleMarkAllAsRead(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    
    now := time.Now()
    s.db.Model(&Notification{}).
        Where("user_id = ? AND read = ?", userID, false).
        Updates(map[string]interface{}{
            "read":    true,
            "read_at": now,
        })

    return c.JSON(fiber.Map{
        "message": "All notifications marked as read",
    })
}

func (s *NotificationService) HandleGetPreferences(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    
    prefs, err := s.getUserPreferences(c.Context(), userID)
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.JSON(prefs)
}

func (s *NotificationService) HandleUpdatePreferences(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    
    var req UserPreferences
    if err := c.BodyParser(&req); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request")
    }

    // Update preferences
    result := s.db.Model(&UserPreferences{}).
        Where("user_id = ?", userID).
        Updates(&req)

    if result.RowsAffected == 0 {
        // Create new preferences
        req.ID = uuid.New()
        req.UserID = userID
        s.db.Create(&req)
    }

    return c.JSON(fiber.Map{
        "message": "Preferences updated successfully",
    })
}

func (s *NotificationService) HandleRegisterPushToken(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    
    var req struct {
        Token    string `json:"token" validate:"required"`
        Platform string `json:"platform" validate:"required"`
        DeviceID string `json:"device_id"`
    }

    if err := c.BodyParser(&req); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request")
    }

    // Check if token already exists
    var existingToken PushToken
    err := s.db.Where("user_id = ? AND token = ?", userID, req.Token).First(&existingToken).Error
    
    if err == gorm.ErrRecordNotFound {
        // Create new token
        token := PushToken{
            ID:       uuid.New(),
            UserID:   userID,
            Token:    req.Token,
            Platform: req.Platform,
            DeviceID: req.DeviceID,
            Active:   true,
        }
        s.db.Create(&token)
    } else if err == nil {
        // Update existing token
        existingToken.Active = true
        existingToken.Platform = req.Platform
        existingToken.DeviceID = req.DeviceID
        s.db.Save(&existingToken)
    } else {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.JSON(fiber.Map{
        "message": "Push token registered successfully",
    })
}

func (s *NotificationService) getUnreadCount(userID uuid.UUID) int64 {
    var count int64
    s.db.Model(&Notification{}).
        Where("user_id = ? AND read = ?", userID, false).
        Count(&count)
    return count
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
    db.AutoMigrate(
        &Notification{},
        &NotificationTemplate{},
        &UserPreferences{},
        &PushToken{},
    )

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

    // Create notification service
    service, err := NewNotificationService(db, redis, rabbit, config)
    if err != nil {
        log.Fatal("Failed to create notification service:", err)
    }

    // Create fiber app
    app := fiber.New(fiber.Config{
        AppName: "VortexPanel Notification Service",
    })

    // Routes
    api := app.Group("/api/v1")
    
    // Internal routes (for other services)
    api.Post("/notifications/send", service.HandleSendNotification)
    
    // User routes (would have auth middleware)
    api.Get("/notifications", service.HandleGetNotifications)
    api.Put("/notifications/:id/read", service.HandleMarkAsRead)
    api.Put("/notifications/read-all", service.HandleMarkAllAsRead)
    api.Get("/notifications/preferences", service.HandleGetPreferences)
    api.Put("/notifications/preferences", service.HandleUpdatePreferences)
    api.Post("/notifications/push-token", service.HandleRegisterPushToken)

    // Health check
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"status": "ok"})
    })

    // Start server
    go func() {
        if err := app.Listen(":8084"); err != nil {
            log.Fatal("Failed to start server:", err)
        }
    }()

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Shutting down notification service...")
    app.Shutdown()
    log.Println("Notification service stopped")
}