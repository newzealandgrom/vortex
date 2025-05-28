// services/billing/main.go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "math"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
    "github.com/robfig/cron/v3"
    "github.com/stripe/stripe-go/v76"
    "github.com/stripe/stripe-go/v76/customer"
    "github.com/stripe/stripe-go/v76/invoice"
    "github.com/stripe/stripe-go/v76/paymentmethod"
    "github.com/stripe/stripe-go/v76/price"
    "github.com/stripe/stripe-go/v76/product"
    "github.com/stripe/stripe-go/v76/subscription"
    "github.com/stripe/stripe-go/v76/webhook"
    "github.com/vortexpanel/shared/models"
    "gorm.io/gorm"
)

// BillingService handles all billing operations
type BillingService struct {
    db           *gorm.DB
    redis        *redis.Client
    stripe       *StripeClient
    paypal       *PayPalClient
    crypto       *CryptoPaymentProcessor
    cron         *cron.Cron
    webhookSecret string
}

// StripeClient wraps Stripe API
type StripeClient struct {
    apiKey string
}

// PayPalClient handles PayPal payments
type PayPalClient struct {
    clientID     string
    clientSecret string
    sandbox      bool
}

// CryptoPaymentProcessor handles cryptocurrency payments
type CryptoPaymentProcessor struct {
    btcAddress  string
    ethAddress  string
    usdtAddress string
    exchangeAPI string
}

// Models
type Plan struct {
    ID           uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
    Name         string         `gorm:"not null" json:"name"`
    Description  string         `json:"description"`
    Price        float64        `gorm:"not null" json:"price"`
    Currency     string         `gorm:"default:'USD'" json:"currency"`
    Interval     BillingInterval `gorm:"not null" json:"interval"`
    TrialDays    int            `gorm:"default:0" json:"trial_days"`
    Features     []PlanFeature  `gorm:"constraint:OnDelete:CASCADE" json:"features"`
    Limits       *PlanLimits    `gorm:"embedded" json:"limits"`
    StripeID     string         `json:"stripe_id,omitempty"`
    PayPalID     string         `json:"paypal_id,omitempty"`
    Active       bool           `gorm:"default:true" json:"active"`
    Popular      bool           `gorm:"default:false" json:"popular"`
    CreatedAt    time.Time      `json:"created_at"`
    UpdatedAt    time.Time      `json:"updated_at"`
}

type BillingInterval string

const (
    IntervalMonthly   BillingInterval = "monthly"
    IntervalQuarterly BillingInterval = "quarterly"
    IntervalYearly    BillingInterval = "yearly"
    IntervalLifetime  BillingInterval = "lifetime"
)

type PlanFeature struct {
    ID          uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
    PlanID      uuid.UUID `gorm:"type:uuid;not null" json:"plan_id"`
    Name        string    `gorm:"not null" json:"name"`
    Description string    `json:"description"`
    Value       string    `json:"value"`
}

type PlanLimits struct {
    MaxClients       int   `json:"max_clients"`
    MaxTrafficGB     int   `json:"max_traffic_gb"`
    MaxBandwidthMbps int   `json:"max_bandwidth_mbps"`
    MaxInbounds      int   `json:"max_inbounds"`
    MaxDevices       int   `json:"max_devices"`
}

type Subscription struct {
    ID                 uuid.UUID           `gorm:"type:uuid;primary_key" json:"id"`
    UserID             uuid.UUID           `gorm:"type:uuid;not null" json:"user_id"`
    PlanID             uuid.UUID           `gorm:"type:uuid;not null" json:"plan_id"`
    Plan               *Plan               `gorm:"constraint:OnDelete:RESTRICT" json:"plan,omitempty"`
    Status             SubscriptionStatus  `gorm:"not null" json:"status"`
    CurrentPeriodStart time.Time           `json:"current_period_start"`
    CurrentPeriodEnd   time.Time           `json:"current_period_end"`
    TrialEnd           *time.Time          `json:"trial_end,omitempty"`
    CancelAtPeriodEnd  bool                `gorm:"default:false" json:"cancel_at_period_end"`
    CanceledAt         *time.Time          `json:"canceled_at,omitempty"`
    PaymentMethodID    *uuid.UUID          `gorm:"type:uuid" json:"payment_method_id,omitempty"`
    PaymentMethod      *PaymentMethod      `gorm:"constraint:OnDelete:SET NULL" json:"payment_method,omitempty"`
    StripeSubID        string              `json:"stripe_sub_id,omitempty"`
    PayPalSubID        string              `json:"paypal_sub_id,omitempty"`
    Metadata           map[string]string   `gorm:"type:jsonb" json:"metadata,omitempty"`
    CreatedAt          time.Time           `json:"created_at"`
    UpdatedAt          time.Time           `json:"updated_at"`
}

type SubscriptionStatus string

const (
    StatusActive           SubscriptionStatus = "active"
    StatusPastDue          SubscriptionStatus = "past_due"
    StatusCanceled         SubscriptionStatus = "canceled"
    StatusIncomplete       SubscriptionStatus = "incomplete"
    StatusIncompleteExpired SubscriptionStatus = "incomplete_expired"
    StatusTrialing         SubscriptionStatus = "trialing"
    StatusUnpaid           SubscriptionStatus = "unpaid"
)

type PaymentMethod struct {
    ID            uuid.UUID          `gorm:"type:uuid;primary_key" json:"id"`
    UserID        uuid.UUID          `gorm:"type:uuid;not null" json:"user_id"`
    Type          PaymentMethodType  `gorm:"not null" json:"type"`
    Provider      string             `gorm:"not null" json:"provider"`
    Last4         string             `json:"last4,omitempty"`
    Brand         string             `json:"brand,omitempty"`
    ExpMonth      int                `json:"exp_month,omitempty"`
    ExpYear       int                `json:"exp_year,omitempty"`
    Email         string             `json:"email,omitempty"`
    CryptoAddress string             `json:"crypto_address,omitempty"`
    IsDefault     bool               `gorm:"default:false" json:"is_default"`
    StripeID      string             `json:"stripe_id,omitempty"`
    PayPalID      string             `json:"paypal_id,omitempty"`
    Metadata      map[string]string  `gorm:"type:jsonb" json:"metadata,omitempty"`
    CreatedAt     time.Time          `json:"created_at"`
}

type PaymentMethodType string

const (
    PaymentCard   PaymentMethodType = "card"
    PaymentBank   PaymentMethodType = "bank"
    PaymentPayPal PaymentMethodType = "paypal"
    PaymentCrypto PaymentMethodType = "crypto"
)

type Payment struct {
    ID              uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
    UserID          uuid.UUID      `gorm:"type:uuid;not null" json:"user_id"`
    SubscriptionID  *uuid.UUID     `gorm:"type:uuid" json:"subscription_id,omitempty"`
    InvoiceID       *uuid.UUID     `gorm:"type:uuid" json:"invoice_id,omitempty"`
    Amount          float64        `gorm:"not null" json:"amount"`
    Currency        string         `gorm:"default:'USD'" json:"currency"`
    Status          PaymentStatus  `gorm:"not null" json:"status"`
    Provider        string         `gorm:"not null" json:"provider"`
    ProviderID      string         `json:"provider_id"`
    PaymentMethodID *uuid.UUID     `gorm:"type:uuid" json:"payment_method_id,omitempty"`
    Description     string         `json:"description"`
    Metadata        map[string]string `gorm:"type:jsonb" json:"metadata,omitempty"`
    FailureReason   string         `json:"failure_reason,omitempty"`
    CreatedAt       time.Time      `json:"created_at"`
    UpdatedAt       time.Time      `json:"updated_at"`
}

type PaymentStatus string

const (
    PaymentPending   PaymentStatus = "pending"
    PaymentSucceeded PaymentStatus = "succeeded"
    PaymentFailed    PaymentStatus = "failed"
    PaymentCanceled  PaymentStatus = "canceled"
    PaymentRefunded  PaymentStatus = "refunded"
)

type Invoice struct {
    ID             uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
    UserID         uuid.UUID      `gorm:"type:uuid;not null" json:"user_id"`
    SubscriptionID uuid.UUID      `gorm:"type:uuid;not null" json:"subscription_id"`
    Number         string         `gorm:"uniqueIndex;not null" json:"number"`
    Status         InvoiceStatus  `gorm:"not null" json:"status"`
    Amount         float64        `gorm:"not null" json:"amount"`
    Tax            float64        `gorm:"default:0" json:"tax"`
    Total          float64        `gorm:"not null" json:"total"`
    Currency       string         `gorm:"default:'USD'" json:"currency"`
    DueDate        time.Time      `json:"due_date"`
    PaidAt         *time.Time     `json:"paid_at,omitempty"`
    LineItems      []InvoiceLineItem `gorm:"constraint:OnDelete:CASCADE" json:"line_items"`
    StripeID       string         `json:"stripe_id,omitempty"`
    PayPalID       string         `json:"paypal_id,omitempty"`
    CreatedAt      time.Time      `json:"created_at"`
    UpdatedAt      time.Time      `json:"updated_at"`
}

type InvoiceStatus string

const (
    InvoiceDraft   InvoiceStatus = "draft"
    InvoiceOpen    InvoiceStatus = "open"
    InvoicePaid    InvoiceStatus = "paid"
    InvoiceVoid    InvoiceStatus = "void"
    InvoiceUncollectible InvoiceStatus = "uncollectible"
)

type InvoiceLineItem struct {
    ID          uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
    InvoiceID   uuid.UUID `gorm:"type:uuid;not null" json:"invoice_id"`
    Description string    `gorm:"not null" json:"description"`
    Quantity    int       `gorm:"default:1" json:"quantity"`
    UnitPrice   float64   `gorm:"not null" json:"unit_price"`
    Amount      float64   `gorm:"not null" json:"amount"`
}

// NewBillingService creates a new billing service
func NewBillingService(db *gorm.DB, redis *redis.Client, config *Config) (*BillingService, error) {
    // Initialize Stripe
    stripe.Key = config.Stripe.SecretKey
    
    stripeClient := &StripeClient{
        apiKey: config.Stripe.SecretKey,
    }

    // Initialize PayPal
    paypalClient := &PayPalClient{
        clientID:     config.PayPal.ClientID,
        clientSecret: config.PayPal.ClientSecret,
        sandbox:      config.PayPal.Sandbox,
    }

    // Initialize Crypto processor
    cryptoProcessor := &CryptoPaymentProcessor{
        btcAddress:  config.Crypto.BTCAddress,
        ethAddress:  config.Crypto.ETHAddress,
        usdtAddress: config.Crypto.USDTAddress,
        exchangeAPI: config.Crypto.ExchangeAPI,
    }

    // Create cron scheduler
    c := cron.New()

    service := &BillingService{
        db:            db,
        redis:         redis,
        stripe:        stripeClient,
        paypal:        paypalClient,
        crypto:        cryptoProcessor,
        cron:          c,
        webhookSecret: config.Stripe.WebhookSecret,
    }

    // Setup cron jobs
    service.setupCronJobs()

    // Start cron
    c.Start()

    return service, nil
}

// Plans management
func (s *BillingService) CreatePlan(ctx context.Context, plan *Plan) error {
    plan.ID = uuid.New()
    
    // Create in Stripe
    if s.stripe.apiKey != "" {
        stripeProduct, err := product.New(&stripe.ProductParams{
            Name:        stripe.String(plan.Name),
            Description: stripe.String(plan.Description),
            Metadata: map[string]string{
                "plan_id": plan.ID.String(),
            },
        })
        
        if err != nil {
            return fmt.Errorf("failed to create Stripe product: %w", err)
        }

        // Create price
        interval := s.getStripeInterval(plan.Interval)
        priceParams := &stripe.PriceParams{
            Product:    stripe.String(stripeProduct.ID),
            Currency:   stripe.String(plan.Currency),
            UnitAmount: stripe.Int64(int64(plan.Price * 100)), // Convert to cents
        }

        if interval != "" {
            priceParams.Recurring = &stripe.PriceRecurringParams{
                Interval: stripe.String(interval),
            }
        }

        stripePrice, err := price.New(priceParams)
        if err != nil {
            return fmt.Errorf("failed to create Stripe price: %w", err)
        }

        plan.StripeID = stripePrice.ID
    }

    // Create in database
    if err := s.db.Create(plan).Error; err != nil {
        return fmt.Errorf("failed to create plan: %w", err)
    }

    // Cache plan
    s.cachePlan(ctx, plan)

    return nil
}

func (s *BillingService) GetPlans(ctx context.Context, active bool) ([]Plan, error) {
    var plans []Plan
    
    query := s.db.Preload("Features")
    if active {
        query = query.Where("active = ?", true)
    }
    
    if err := query.Order("price ASC").Find(&plans).Error; err != nil {
        return nil, fmt.Errorf("failed to get plans: %w", err)
    }

    return plans, nil
}

// Subscription management
func (s *BillingService) CreateSubscription(ctx context.Context, userID uuid.UUID, planID uuid.UUID, paymentMethodID *uuid.UUID) (*Subscription, error) {
    // Get plan
    var plan Plan
    if err := s.db.First(&plan, planID).Error; err != nil {
        return nil, fmt.Errorf("plan not found: %w", err)
    }

    // Get user
    var user models.User
    if err := s.db.First(&user, userID).Error; err != nil {
        return nil, fmt.Errorf("user not found: %w", err)
    }

    // Get payment method
    var pm *PaymentMethod
    if paymentMethodID != nil {
        var paymentMethod PaymentMethod
        if err := s.db.First(&paymentMethod, *paymentMethodID).Error; err != nil {
            return nil, fmt.Errorf("payment method not found: %w", err)
        }
        pm = &paymentMethod
    }

    // Calculate dates
    now := time.Now()
    var currentPeriodEnd time.Time
    var trialEnd *time.Time

    if plan.TrialDays > 0 {
        trialEndTime := now.AddDate(0, 0, plan.TrialDays)
        trialEnd = &trialEndTime
        currentPeriodEnd = trialEndTime
    } else {
        currentPeriodEnd = s.calculatePeriodEnd(now, plan.Interval)
    }

    // Create subscription
    sub := &Subscription{
        ID:                 uuid.New(),
        UserID:             userID,
        PlanID:             planID,
        Status:             StatusActive,
        CurrentPeriodStart: now,
        CurrentPeriodEnd:   currentPeriodEnd,
        TrialEnd:           trialEnd,
        PaymentMethodID:    paymentMethodID,
    }

    if trialEnd != nil {
        sub.Status = StatusTrialing
    }

    // Create in payment provider
    if pm != nil && pm.Provider == "stripe" && plan.StripeID != "" {
        // Create Stripe subscription
        params := &stripe.SubscriptionParams{
            Customer: stripe.String(s.getOrCreateStripeCustomer(ctx, &user)),
            Items: []*stripe.SubscriptionItemsParams{
                {
                    Price: stripe.String(plan.StripeID),
                },
            },
            DefaultPaymentMethod: stripe.String(pm.StripeID),
            Metadata: map[string]string{
                "user_id": userID.String(),
                "plan_id": planID.String(),
            },
        }

        if trialEnd != nil {
            params.TrialEnd = stripe.Int64(trialEnd.Unix())
        }

        stripeSub, err := subscription.New(params)
        if err != nil {
            return nil, fmt.Errorf("failed to create Stripe subscription: %w", err)
        }

        sub.StripeSubID = stripeSub.ID
    }

    // Save to database
    if err := s.db.Create(sub).Error; err != nil {
        return nil, fmt.Errorf("failed to create subscription: %w", err)
    }

    // Update user limits based on plan
    s.updateUserLimits(ctx, userID, &plan)

    // Send confirmation email
    s.sendSubscriptionConfirmation(ctx, &user, sub, &plan)

    return sub, nil
}

func (s *BillingService) CancelSubscription(ctx context.Context, subID uuid.UUID, immediately bool) error {
    var sub Subscription
    if err := s.db.Preload("Plan").First(&sub, subID).Error; err != nil {
        return fmt.Errorf("subscription not found: %w", err)
    }

    if immediately {
        sub.Status = StatusCanceled
        sub.CanceledAt = &time.Time{}
        *sub.CanceledAt = time.Now()
    } else {
        sub.CancelAtPeriodEnd = true
    }

    // Cancel in payment provider
    if sub.StripeSubID != "" {
        params := &stripe.SubscriptionCancelParams{
            Params: stripe.Params{
                Context: ctx,
            },
        }
        
        if immediately {
            params.Prorate = stripe.Bool(true)
        } else {
            params.CancelAtPeriodEnd = stripe.Bool(true)
        }

        _, err := subscription.Cancel(sub.StripeSubID, params)
        if err != nil {
            log.Printf("Failed to cancel Stripe subscription: %v", err)
        }
    }

    // Update database
    if err := s.db.Save(&sub).Error; err != nil {
        return fmt.Errorf("failed to update subscription: %w", err)
    }

    // Send cancellation email
    var user models.User
    s.db.First(&user, sub.UserID)
    s.sendCancellationEmail(ctx, &user, &sub)

    return nil
}

// Payment processing
func (s *BillingService) ProcessPayment(ctx context.Context, payment *Payment) error {
    payment.ID = uuid.New()
    payment.Status = PaymentPending
    payment.CreatedAt = time.Now()

    // Save initial payment record
    if err := s.db.Create(payment).Error; err != nil {
        return fmt.Errorf("failed to create payment record: %w", err)
    }

    // Process based on provider
    var err error
    switch payment.Provider {
    case "stripe":
        err = s.processStripePayment(ctx, payment)
    case "paypal":
        err = s.processPayPalPayment(ctx, payment)
    case "crypto":
        err = s.processCryptoPayment(ctx, payment)
    default:
        err = fmt.Errorf("unsupported payment provider: %s", payment.Provider)
    }

    if err != nil {
        payment.Status = PaymentFailed
        payment.FailureReason = err.Error()
    } else {
        payment.Status = PaymentSucceeded
        
        // Update related subscription if applicable
        if payment.SubscriptionID != nil {
            s.handleSuccessfulPayment(ctx, payment)
        }
    }

    // Update payment record
    s.db.Save(payment)

    return err
}

func (s *BillingService) processStripePayment(ctx context.Context, payment *Payment) error {
    // Implementation for Stripe payment processing
    // This would involve creating a PaymentIntent, confirming it, etc.
    return nil
}

func (s *BillingService) processPayPalPayment(ctx context.Context, payment *Payment) error {
    // Implementation for PayPal payment processing
    return nil
}

func (s *BillingService) processCryptoPayment(ctx context.Context, payment *Payment) error {
    // Implementation for cryptocurrency payment processing
    return nil
}

// Webhook handlers
func (s *BillingService) HandleStripeWebhook(c *fiber.Ctx) error {
    payload := c.Body()
    sigHeader := c.Get("Stripe-Signature")

    event, err := webhook.ConstructEvent(payload, sigHeader, s.webhookSecret)
    if err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid webhook signature")
    }

    switch event.Type {
    case "payment_intent.succeeded":
        // Handle successful payment
        var paymentIntent stripe.PaymentIntent
        if err := json.Unmarshal(event.Data.Raw, &paymentIntent); err != nil {
            return fiber.NewError(fiber.StatusBadRequest, "Invalid payment intent data")
        }
        
        s.handleStripePaymentSuccess(c.Context(), &paymentIntent)

    case "payment_intent.payment_failed":
        // Handle failed payment
        var paymentIntent stripe.PaymentIntent
        if err := json.Unmarshal(event.Data.Raw, &paymentIntent); err != nil {
            return fiber.NewError(fiber.StatusBadRequest, "Invalid payment intent data")
        }
        
        s.handleStripePaymentFailure(c.Context(), &paymentIntent)

    case "customer.subscription.created":
    case "customer.subscription.updated":
    case "customer.subscription.deleted":
        // Handle subscription events
        var sub stripe.Subscription
        if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
            return fiber.NewError(fiber.StatusBadRequest, "Invalid subscription data")
        }
        
        s.handleStripeSubscriptionUpdate(c.Context(), &sub)

    case "invoice.payment_succeeded":
        // Handle invoice payment
        var inv stripe.Invoice
        if err := json.Unmarshal(event.Data.Raw, &inv); err != nil {
            return fiber.NewError(fiber.StatusBadRequest, "Invalid invoice data")
        }
        
        s.handleStripeInvoicePayment(c.Context(), &inv)
    }

    return c.SendStatus(fiber.StatusOK)
}

// Cron jobs
func (s *BillingService) setupCronJobs() {
    // Check expiring subscriptions daily
    s.cron.AddFunc("0 0 * * *", func() {
        s.checkExpiringSubscriptions()
    })

    // Process recurring payments
    s.cron.AddFunc("0 */6 * * *", func() {
        s.processRecurringPayments()
    })

    // Send payment reminders
    s.cron.AddFunc("0 9 * * *", func() {
        s.sendPaymentReminders()
    })

    // Clean up old payment records
    s.cron.AddFunc("0 2 * * 0", func() {
        s.cleanupOldRecords()
    })
}

func (s *BillingService) checkExpiringSubscriptions() {
    ctx := context.Background()
    
    // Find subscriptions expiring in next 7 days
    var subs []Subscription
    s.db.Where("current_period_end BETWEEN ? AND ? AND cancel_at_period_end = false", 
        time.Now(), 
        time.Now().AddDate(0, 0, 7),
    ).Preload("Plan").Find(&subs)

    for _, sub := range subs {
        // Send reminder email
        var user models.User
        if err := s.db.First(&user, sub.UserID).Error; err != nil {
            continue
        }

        s.sendExpirationReminder(ctx, &user, &sub)
    }
}

// API Handlers
func (s *BillingService) HandleGetPlans(c *fiber.Ctx) error {
    plans, err := s.GetPlans(c.Context(), true)
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.JSON(plans)
}

func (s *BillingService) HandleCreateSubscription(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)

    var req struct {
        PlanID          uuid.UUID  `json:"plan_id" validate:"required"`
        PaymentMethodID *uuid.UUID `json:"payment_method_id"`
    }

    if err := c.BodyParser(&req); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request")
    }

    sub, err := s.CreateSubscription(c.Context(), userID, req.PlanID, req.PaymentMethodID)
    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.Status(fiber.StatusCreated).JSON(sub)
}

func (s *BillingService) HandleCancelSubscription(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    subID, err := uuid.Parse(c.Params("id"))
    if err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid subscription ID")
    }

    // Verify ownership
    var sub Subscription
    if err := s.db.Where("id = ? AND user_id = ?", subID, userID).First(&sub).Error; err != nil {
        return fiber.NewError(fiber.StatusNotFound, "Subscription not found")
    }

    immediately := c.QueryBool("immediately", false)
    
    if err := s.CancelSubscription(c.Context(), subID, immediately); err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.JSON(fiber.Map{
        "message": "Subscription canceled successfully",
    })
}

func (s *BillingService) HandleGetInvoices(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)
    
    page := c.QueryInt("page", 1)
    limit := c.QueryInt("limit", 20)
    offset := (page - 1) * limit

    var invoices []Invoice
    var total int64

    s.db.Model(&Invoice{}).Where("user_id = ?", userID).Count(&total)
    s.db.Where("user_id = ?", userID).
        Preload("LineItems").
        Order("created_at DESC").
        Offset(offset).
        Limit(limit).
        Find(&invoices)

    return c.JSON(fiber.Map{
        "invoices": invoices,
        "total":    total,
        "page":     page,
        "limit":    limit,
    })
}

func (s *BillingService) HandleAddPaymentMethod(c *fiber.Ctx) error {
    userID := c.Locals("userID").(uuid.UUID)

    var req struct {
        Type     PaymentMethodType `json:"type" validate:"required"`
        Provider string            `json:"provider" validate:"required"`
        Token    string            `json:"token" validate:"required"`
    }

    if err := c.BodyParser(&req); err != nil {
        return fiber.NewError(fiber.StatusBadRequest, "Invalid request")
    }

    // Process based on provider
    var pm *PaymentMethod
    var err error

    switch req.Provider {
    case "stripe":
        pm, err = s.addStripePaymentMethod(c.Context(), userID, req.Token)
    case "paypal":
        pm, err = s.addPayPalPaymentMethod(c.Context(), userID, req.Token)
    default:
        err = fmt.Errorf("unsupported provider: %s", req.Provider)
    }

    if err != nil {
        return fiber.NewError(fiber.StatusInternalServerError, err.Error())
    }

    return c.Status(fiber.StatusCreated).JSON(pm)
}

// Helper methods
func (s *BillingService) getStripeInterval(interval BillingInterval) string {
    switch interval {
    case IntervalMonthly:
        return "month"
    case IntervalQuarterly:
        return "month" // Will handle with interval_count
    case IntervalYearly:
        return "year"
    default:
        return ""
    }
}

func (s *BillingService) calculatePeriodEnd(start time.Time, interval BillingInterval) time.Time {
    switch interval {
    case IntervalMonthly:
        return start.AddDate(0, 1, 0)
    case IntervalQuarterly:
        return start.AddDate(0, 3, 0)
    case IntervalYearly:
        return start.AddDate(1, 0, 0)
    default:
        return start.AddDate(0, 1, 0)
    }
}

func (s *BillingService) getOrCreateStripeCustomer(ctx context.Context, user *models.User) string {
    // Check if customer already exists
    var customerID string
    key := fmt.Sprintf("stripe:customer:%s", user.ID)
    
    if val, err := s.redis.Get(ctx, key).Result(); err == nil {
        return val
    }

    // Create new customer
    params := &stripe.CustomerParams{
        Email: stripe.String(user.Email),
        Name:  stripe.String(user.Username),
        Metadata: map[string]string{
            "user_id": user.ID.String(),
        },
    }

    cust, err := customer.New(params)
    if err != nil {
        log.Printf("Failed to create Stripe customer: %v", err)
        return ""
    }

    // Cache customer ID
    s.redis.Set(ctx, key, cust.ID, 0)

    return cust.ID
}

func (s *BillingService) updateUserLimits(ctx context.Context, userID uuid.UUID, plan *Plan) {
    // Update user limits based on plan
    // This would update the user's resource limits in the system
}

func (s *BillingService) cachePlan(ctx context.Context, plan *Plan) {
    key := fmt.Sprintf("plan:%s", plan.ID)
    data, _ := json.Marshal(plan)
    s.redis.Set(ctx, key, data, 24*time.Hour)
}

// Email notifications
func (s *BillingService) sendSubscriptionConfirmation(ctx context.Context, user *models.User, sub *Subscription, plan *Plan) {
    // Send confirmation email
}

func (s *BillingService) sendCancellationEmail(ctx context.Context, user *models.User, sub *Subscription) {
    // Send cancellation email
}

func (s *BillingService) sendExpirationReminder(ctx context.Context, user *models.User, sub *Subscription) {
    // Send expiration reminder
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
        &Plan{},
        &PlanFeature{},
        &Subscription{},
        &PaymentMethod{},
        &Payment{},
        &Invoice{},
        &InvoiceLineItem{},
    )

    // Connect to Redis
    redis := redis.NewClient(&redis.Options{
        Addr:     config.Redis.Addr,
        Password: config.Redis.Password,
        DB:       config.Redis.DB,
    })

    // Create billing service
    service, err := NewBillingService(db, redis, config)
    if err != nil {
        log.Fatal("Failed to create billing service:", err)
    }

    // Create fiber app
    app := fiber.New(fiber.Config{
        AppName: "VortexPanel Billing Service",
    })

    // Routes
    api := app.Group("/api/v1")

    // Public routes
    api.Get("/plans", service.HandleGetPlans)
    
    // Protected routes (would have auth middleware)
    api.Post("/subscriptions", service.HandleCreateSubscription)
    api.Delete("/subscriptions/:id", service.HandleCancelSubscription)
    api.Get("/invoices", service.HandleGetInvoices)
    api.Post("/payment-methods", service.HandleAddPaymentMethod)
    
    // Webhook endpoints
    api.Post("/webhooks/stripe", service.HandleStripeWebhook)
    api.Post("/webhooks/paypal", service.HandlePayPalWebhook)

    // Health check
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"status": "ok"})
    })

    // Start server
    go func() {
        if err := app.Listen(":8083"); err != nil {
            log.Fatal("Failed to start server:", err)
        }
    }()

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Shutting down billing service...")
    service.cron.Stop()
    app.Shutdown()
    log.Println("Billing service stopped")
}