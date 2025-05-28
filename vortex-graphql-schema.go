// graphql/schema.graphql
"""
VortexPanel GraphQL Schema
"""
scalar Time
scalar UUID
scalar JSON

type Query {
  # User queries
  me: User!
  users(filter: UserFilter, pagination: PaginationInput): UserConnection!
  user(id: UUID!): User
  
  # Client queries
  clients(filter: ClientFilter, pagination: PaginationInput): ClientConnection!
  client(id: UUID!): Client
  
  # Inbound queries
  inbounds(filter: InboundFilter): [Inbound!]!
  inbound(id: UUID!): Inbound
  
  # Analytics queries
  analytics(period: TimePeriod!): AnalyticsOverview!
  trafficStats(clientId: UUID, period: TimePeriod!): TrafficStats!
  predictions(clientId: UUID!, days: Int!): TrafficPrediction!
  anomalies(threshold: Float!): [Anomaly!]!
  
  # System queries
  systemStatus: SystemStatus!
  healthCheck: HealthStatus!
  logs(filter: LogFilter, pagination: PaginationInput): LogConnection!
  
  # Billing queries
  subscription(userId: UUID!): Subscription
  invoices(userId: UUID!, pagination: PaginationInput): InvoiceConnection!
  paymentMethods(userId: UUID!): [PaymentMethod!]!
}

type Mutation {
  # Authentication
  login(input: LoginInput!): AuthPayload!
  logout: Boolean!
  refreshToken(token: String!): AuthPayload!
  setup2FA: TwoFactorSetup!
  verify2FA(code: String!): Boolean!
  
  # User management
  createUser(input: CreateUserInput!): User!
  updateUser(id: UUID!, input: UpdateUserInput!): User!
  deleteUser(id: UUID!): Boolean!
  resetPassword(id: UUID!): String!
  
  # Client management
  createClient(input: CreateClientInput!): Client!
  updateClient(id: UUID!, input: UpdateClientInput!): Client!
  deleteClient(id: UUID!): Boolean!
  resetClientTraffic(id: UUID!): Boolean!
  
  # Inbound management
  createInbound(input: CreateInboundInput!): Inbound!
  updateInbound(id: UUID!, input: UpdateInboundInput!): Inbound!
  deleteInbound(id: UUID!): Boolean!
  restartInbound(id: UUID!): Boolean!
  
  # System operations
  restartService(service: ServiceType!): Boolean!
  backupDatabase: BackupResult!
  restoreDatabase(backupId: String!): Boolean!
  updateSettings(input: SettingsInput!): Settings!
  
  # Billing operations
  createSubscription(input: CreateSubscriptionInput!): Subscription!
  cancelSubscription(id: UUID!): Boolean!
  addPaymentMethod(input: PaymentMethodInput!): PaymentMethod!
  removePaymentMethod(id: UUID!): Boolean!
  processPayment(input: PaymentInput!): Payment!
}

type Subscription {
  # Real-time monitoring
  systemMetrics: SystemMetrics!
  userTraffic(userId: UUID!): TrafficUpdate!
  clientTraffic(clientId: UUID!): TrafficUpdate!
  serverStatus(serverId: UUID!): ServerStatus!
  
  # Notifications
  notifications(userId: UUID!): Notification!
  
  # Logs
  logStream(filter: LogFilter): LogEntry!
}

# User types
type User {
  id: UUID!
  email: String!
  username: String!
  role: UserRole!
  status: UserStatus!
  profile: UserProfile
  subscription: Subscription
  clients: [Client!]!
  twoFactorEnabled: Boolean!
  createdAt: Time!
  updatedAt: Time!
}

type UserProfile {
  id: UUID!
  firstName: String
  lastName: String
  avatar: String
  language: String!
  timezone: String!
  notificationPrefs: NotificationPreferences!
}

type NotificationPreferences {
  email: Boolean!
  push: Boolean!
  telegram: Boolean!
  events: [NotificationEvent!]!
}

enum UserRole {
  ADMIN
  MODERATOR
  USER
}

enum UserStatus {
  ACTIVE
  SUSPENDED
  DELETED
}

# Client types
type Client {
  id: UUID!
  user: User!
  inbound: Inbound!
  email: String!
  uuid: String!
  password: String
  flow: String
  limitIP: Int!
  totalGB: Int!
  expiryTime: Time
  enable: Boolean!
  tgId: String
  subId: String
  reset: Int!
  trafficStats: TrafficStats!
  connectionLogs(pagination: PaginationInput): ConnectionLogConnection!
  createdAt: Time!
  updatedAt: Time!
}

type TrafficStats {
  clientId: UUID!
  period: TimePeriod!
  upload: Int!
  download: Int!
  total: Int!
  points: [TrafficPoint!]!
}

type TrafficPoint {
  time: Time!
  upload: Int!
  download: Int!
}

type ConnectionLog {
  id: UUID!
  ip: String!
  country: String!
  city: String!
  userAgent: String!
  connectedAt: Time!
  disconnectedAt: Time
  duration: Int
}

# Inbound types
type Inbound {
  id: UUID!
  user: User!
  remark: String!
  enable: Boolean!
  protocol: Protocol!
  settings: JSON!
  streamSettings: StreamSettings!
  tag: String!
  sniffing: SniffingConfig
  listen: String!
  port: Int!
  clients: [Client!]!
  stats: InboundStats!
  createdAt: Time!
  updatedAt: Time!
}

type StreamSettings {
  network: NetworkType!
  security: SecurityType!
  tlsSettings: TLSSettings
  realitySettings: RealitySettings
  wsSettings: WebSocketSettings
  grpcSettings: GRPCSettings
  httpSettings: HTTPSettings
  tcpSettings: TCPSettings
  kcpSettings: KCPSettings
  quicSettings: QUICSettings
}

type TLSSettings {
  serverName: String
  certificates: [Certificate!]!
  alpn: [String!]!
  minVersion: String
  maxVersion: String
  cipherSuites: [String!]!
  fingerprint: String
}

type RealitySettings {
  show: Boolean!
  dest: String!
  xver: Int!
  serverNames: [String!]!
  privateKey: String!
  minClientVer: String
  maxClientVer: String
  maxTimeDiff: Int!
  shortIds: [String!]!
}

enum Protocol {
  VMESS
  VLESS
  TROJAN
  SHADOWSOCKS
  DOKODEMO
  SOCKS
  HTTP
  WIREGUARD
}

enum NetworkType {
  TCP
  WS
  HTTP
  H2
  GRPC
  QUIC
  KCP
  HTTPUPGRADE
  XHTTP
}

enum SecurityType {
  NONE
  TLS
  REALITY
  XTLS
}

# Analytics types
type AnalyticsOverview {
  period: TimePeriod!
  systemMetrics: SystemMetrics!
  topUsers: [UserTraffic!]!
  trafficTrend: [TrendPoint!]!
  anomalies: [Anomaly!]!
  predictions: TrafficPrediction
}

type SystemMetrics {
  timestamp: Time!
  activeUsers: Int!
  activeConnections: Int!
  totalTraffic: Int!
  bandwidthUsage: Float!
  cpuUsage: Float!
  memoryUsage: Float!
  diskUsage: Float!
}

type TrafficPrediction {
  clientId: UUID!
  days: Int!
  predictions: [DailyPrediction!]!
  confidence: Float!
}

type DailyPrediction {
  date: Time!
  traffic: Int!
  confidence: Float!
  upperBound: Int!
  lowerBound: Int!
}

type Anomaly {
  clientId: UUID!
  timestamp: Time!
  value: Float!
  type: AnomalyType!
  severity: Severity!
  description: String!
}

enum AnomalyType {
  TRAFFIC_SPIKE
  TRAFFIC_DROP
  UNUSUAL_PATTERN
  SECURITY_THREAT
}

enum Severity {
  LOW
  MEDIUM
  HIGH
  CRITICAL
}

# Billing types
type Subscription {
  id: UUID!
  user: User!
  plan: Plan!
  status: SubscriptionStatus!
  currentPeriodStart: Time!
  currentPeriodEnd: Time!
  cancelAtPeriodEnd: Boolean!
  paymentMethod: PaymentMethod
  invoices: [Invoice!]!
}

type Plan {
  id: UUID!
  name: String!
  description: String!
  price: Float!
  currency: String!
  interval: BillingInterval!
  features: [Feature!]!
  limits: PlanLimits!
}

type PlanLimits {
  maxClients: Int!
  maxTrafficGB: Int!
  maxBandwidthMbps: Int!
  maxInbounds: Int!
}

enum SubscriptionStatus {
  ACTIVE
  PAST_DUE
  CANCELED
  INCOMPLETE
  INCOMPLETE_EXPIRED
  TRIALING
  UNPAID
}

enum BillingInterval {
  MONTHLY
  QUARTERLY
  YEARLY
}

# System types
type SystemStatus {
  version: String!
  uptime: Int!
  services: [ServiceStatus!]!
  resources: ResourceUsage!
  cluster: ClusterStatus
}

type ServiceStatus {
  name: String!
  status: ServiceState!
  uptime: Int!
  lastRestart: Time
  errorCount: Int!
}

enum ServiceState {
  RUNNING
  STOPPED
  RESTARTING
  ERROR
}

type HealthStatus {
  status: HealthState!
  checks: [HealthCheck!]!
  timestamp: Time!
}

enum HealthState {
  HEALTHY
  DEGRADED
  UNHEALTHY
}

type HealthCheck {
  name: String!
  status: HealthState!
  message: String
  lastCheck: Time!
}

# Notification types
type Notification {
  id: UUID!
  userId: UUID!
  type: NotificationType!
  title: String!
  message: String!
  data: JSON
  read: Boolean!
  createdAt: Time!
}

enum NotificationType {
  INFO
  WARNING
  ERROR
  SUCCESS
  TRAFFIC_LIMIT
  EXPIRY_WARNING
  PAYMENT_DUE
  SYSTEM_UPDATE
}

# Input types
input LoginInput {
  username: String!
  password: String!
  totpCode: String
  rememberMe: Boolean
}

input CreateUserInput {
  email: String!
  username: String!
  password: String!
  role: UserRole!
  profile: UserProfileInput
}

input UpdateUserInput {
  email: String
  username: String
  password: String
  role: UserRole
  status: UserStatus
  profile: UserProfileInput
}

input UserProfileInput {
  firstName: String
  lastName: String
  avatar: String
  language: String
  timezone: String
  notificationPrefs: NotificationPreferencesInput
}

input CreateClientInput {
  userId: UUID!
  inboundId: UUID!
  email: String!
  password: String
  flow: String
  limitIP: Int
  totalGB: Int
  expiryTime: Time
  enable: Boolean
}

input UpdateClientInput {
  email: String
  password: String
  flow: String
  limitIP: Int
  totalGB: Int
  expiryTime: Time
  enable: Boolean
  reset: Boolean
}

input CreateInboundInput {
  userId: UUID!
  remark: String!
  protocol: Protocol!
  settings: JSON!
  streamSettings: StreamSettingsInput!
  listen: String!
  port: Int!
  sniffing: SniffingConfigInput
}

input StreamSettingsInput {
  network: NetworkType!
  security: SecurityType!
  tlsSettings: TLSSettingsInput
  realitySettings: RealitySettingsInput
  wsSettings: JSON
  grpcSettings: JSON
  httpSettings: JSON
  tcpSettings: JSON
  kcpSettings: JSON
  quicSettings: JSON
}

# Filter inputs
input UserFilter {
  role: UserRole
  status: UserStatus
  search: String
}

input ClientFilter {
  userId: UUID
  inboundId: UUID
  enable: Boolean
  expired: Boolean
  search: String
}

input InboundFilter {
  userId: UUID
  protocol: Protocol
  enable: Boolean
  search: String
}

input LogFilter {
  level: LogLevel
  service: String
  startTime: Time
  endTime: Time
  search: String
}

enum LogLevel {
  DEBUG
  INFO
  WARNING
  ERROR
  CRITICAL
}

# Pagination
input PaginationInput {
  page: Int!
  limit: Int!
  sortBy: String
  sortOrder: SortOrder
}

enum SortOrder {
  ASC
  DESC
}

type PageInfo {
  page: Int!
  limit: Int!
  total: Int!
  totalPages: Int!
  hasNext: Boolean!
  hasPrev: Boolean!
}

# Connection types
type UserConnection {
  nodes: [User!]!
  pageInfo: PageInfo!
}

type ClientConnection {
  nodes: [Client!]!
  pageInfo: PageInfo!
}

type ConnectionLogConnection {
  nodes: [ConnectionLog!]!
  pageInfo: PageInfo!
}

type LogConnection {
  nodes: [LogEntry!]!
  pageInfo: PageInfo!
}

type InvoiceConnection {
  nodes: [Invoice!]!
  pageInfo: PageInfo!
}

# graphql/resolvers.go
package graphql

import (
    "context"
    "time"
    
    "github.com/99designs/gqlgen/graphql"
    "github.com/google/uuid"
    "github.com/vortexpanel/core/models"
    "github.com/vortexpanel/core/services"
)

type Resolver struct {
    services *services.Manager
}

func NewResolver(services *services.Manager) *Resolver {
    return &Resolver{services: services}
}

// Query resolvers
func (r *queryResolver) Me(ctx context.Context) (*models.User, error) {
    userID := ctx.Value("userID").(uuid.UUID)
    return r.services.Users.GetByID(ctx, userID)
}

func (r *queryResolver) Users(ctx context.Context, filter *UserFilter, pagination *PaginationInput) (*UserConnection, error) {
    users, total, err := r.services.Users.List(ctx, filter, pagination)
    if err != nil {
        return nil, err
    }
    
    return &UserConnection{
        Nodes: users,
        PageInfo: &PageInfo{
            Page:       pagination.Page,
            Limit:      pagination.Limit,
            Total:      total,
            TotalPages: (total + pagination.Limit - 1) / pagination.Limit,
            HasNext:    pagination.Page < (total+pagination.Limit-1)/pagination.Limit,
            HasPrev:    pagination.Page > 1,
        },
    }, nil
}

func (r *queryResolver) Analytics(ctx context.Context, period TimePeriod) (*AnalyticsOverview, error) {
    return r.services.Analytics.GetOverview(ctx, period)
}

func (r *queryResolver) TrafficStats(ctx context.Context, clientID *uuid.UUID, period TimePeriod) (*TrafficStats, error) {
    if clientID != nil {
        return r.services.Analytics.GetClientTrafficStats(ctx, *clientID, period)
    }
    return r.services.Analytics.GetGlobalTrafficStats(ctx, period)
}

func (r *queryResolver) SystemStatus(ctx context.Context) (*SystemStatus, error) {
    return r.services.System.GetStatus(ctx)
}

// Mutation resolvers
func (r *mutationResolver) Login(ctx context.Context, input LoginInput) (*AuthPayload, error) {
    user, tokens, err := r.services.Auth.Login(ctx, input.Username, input.Password, input.TotpCode)
    if err != nil {
        return nil, err
    }
    
    return &AuthPayload{
        User:         user,
        AccessToken:  tokens.AccessToken,
        RefreshToken: tokens.RefreshToken,
        ExpiresIn:    tokens.ExpiresIn,
    }, nil
}

func (r *mutationResolver) CreateUser(ctx context.Context, input CreateUserInput) (*models.User, error) {
    return r.services.Users.Create(ctx, &models.User{
        Email:    input.Email,
        Username: input.Username,
        Role:     models.UserRole(input.Role),
    }, input.Password)
}

func (r *mutationResolver) CreateClient(ctx context.Context, input CreateClientInput) (*models.Client, error) {
    client := &models.Client{
        UserID:     input.UserID,
        InboundID:  input.InboundID,
        Email:      input.Email,
        UUID:       generateUUID(),
        Password:   input.Password,
        Flow:       input.Flow,
        LimitIP:    input.LimitIP,
        TotalGB:    input.TotalGB,
        ExpiryTime: input.ExpiryTime,
        Enable:     input.Enable,
    }
    
    return r.services.Clients.Create(ctx, client)
}

func (r *mutationResolver) CreateInbound(ctx context.Context, input CreateInboundInput) (*models.Inbound, error) {
    inbound := &models.Inbound{
        UserID:         input.UserID,
        Remark:         input.Remark,
        Protocol:       models.Protocol(input.Protocol),
        Settings:       input.Settings,
        StreamSettings: input.StreamSettings,
        Listen:         input.Listen,
        Port:           input.Port,
        Enable:         true,
        Tag:            generateTag(input.Remark),
    }
    
    return r.services.Inbounds.Create(ctx, inbound)
}

func (r *mutationResolver) RestartService(ctx context.Context, service ServiceType) (bool, error) {
    return r.services.System.RestartService(ctx, string(service))
}

// Subscription resolvers
func (r *subscriptionResolver) SystemMetrics(ctx context.Context) (<-chan *SystemMetrics, error) {
    metrics := make(chan *SystemMetrics)
    
    go func() {
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()
        defer close(metrics)
        
        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                m, err := r.services.Analytics.GetSystemMetrics(ctx)
                if err == nil {
                    metrics <- m
                }
            }
        }
    }()
    
    return metrics, nil
}

func (r *subscriptionResolver) UserTraffic(ctx context.Context, userID uuid.UUID) (<-chan *TrafficUpdate, error) {
    updates := make(chan *TrafficUpdate)
    
    go func() {
        sub := r.services.PubSub.Subscribe(ctx, "traffic:"+userID.String())
        defer sub.Close()
        defer close(updates)
        
        for {
            select {
            case <-ctx.Done():
                return
            case msg := <-sub.Channel():
                var update TrafficUpdate
                if err := json.Unmarshal([]byte(msg.Payload), &update); err == nil {
                    updates <- &update
                }
            }
        }
    }()
    
    return updates, nil
}

func (r *subscriptionResolver) Notifications(ctx context.Context, userID uuid.UUID) (<-chan *Notification, error) {
    notifications := make(chan *Notification)
    
    go func() {
        sub := r.services.PubSub.Subscribe(ctx, "notifications:"+userID.String())
        defer sub.Close()
        defer close(notifications)
        
        for {
            select {
            case <-ctx.Done():
                return
            case msg := <-sub.Channel():
                var notification Notification
                if err := json.Unmarshal([]byte(msg.Payload), &notification); err == nil {
                    notifications <- &notification
                }
            }
        }
    }()
    
    return notifications, nil
}

// Field resolvers
func (r *userResolver) Clients(ctx context.Context, obj *models.User) ([]*models.Client, error) {
    return r.services.Clients.GetByUserID(ctx, obj.ID)
}

func (r *userResolver) Subscription(ctx context.Context, obj *models.User) (*models.Subscription, error) {
    return r.services.Billing.GetSubscription(ctx, obj.ID)
}

func (r *clientResolver) TrafficStats(ctx context.Context, obj *models.Client) (*TrafficStats, error) {
    return r.services.Analytics.GetClientTrafficStats(ctx, obj.ID, TimePeriod24H)
}

func (r *clientResolver) ConnectionLogs(ctx context.Context, obj *models.Client, pagination *PaginationInput) (*ConnectionLogConnection, error) {
    logs, total, err := r.services.Logs.GetConnectionLogs(ctx, obj.ID, pagination)
    if err != nil {
        return nil, err
    }
    
    return &ConnectionLogConnection{
        Nodes: logs,
        PageInfo: &PageInfo{
            Page:       pagination.Page,
            Limit:      pagination.Limit,
            Total:      total,
            TotalPages: (total + pagination.Limit - 1) / pagination.Limit,
            HasNext:    pagination.Page < (total+pagination.Limit-1)/pagination.Limit,
            HasPrev:    pagination.Page > 1,
        },
    }, nil
}

func (r *inboundResolver) Clients(ctx context.Context, obj *models.Inbound) ([]*models.Client, error) {
    return r.services.Clients.GetByInboundID(ctx, obj.ID)
}

func (r *inboundResolver) Stats(ctx context.Context, obj *models.Inbound) (*InboundStats, error) {
    return r.services.Analytics.GetInboundStats(ctx, obj.ID)
}

// Helper functions
func generateUUID() string {
    return uuid.New().String()
}

func generateTag(remark string) string {
    // Generate unique tag from remark
    return fmt.Sprintf("%s-%d", strings.ToLower(strings.ReplaceAll(remark, " ", "-")), time.Now().Unix())
}

// Directive implementations
func (r *Resolver) HasRole(ctx context.Context, obj interface{}, next graphql.Resolver, roles []UserRole) (interface{}, error) {
    userID := ctx.Value("userID").(uuid.UUID)
    user, err := r.services.Users.GetByID(ctx, userID)
    if err != nil {
        return nil, err
    }
    
    for _, role := range roles {
        if user.Role == models.UserRole(role) {
            return next(ctx)
        }
    }
    
    return nil, fmt.Errorf("insufficient permissions")
}

func (r *Resolver) RateLimit(ctx context.Context, obj interface{}, next graphql.Resolver, limit int, window string) (interface{}, error) {
    userID := ctx.Value("userID").(uuid.UUID)
    
    allowed, err := r.services.RateLimiter.Allow(ctx, userID.String(), limit, window)
    if err != nil {
        return nil, err
    }
    
    if !allowed {
        return nil, fmt.Errorf("rate limit exceeded")
    }
    
    return next(ctx)
}