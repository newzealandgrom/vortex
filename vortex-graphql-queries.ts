import { gql } from '@apollo/client'

// Фрагменты
export const USER_FRAGMENT = gql`
  fragment UserFields on User {
    id
    email
    username
    role
    status
    profile {
      firstName
      lastName
      avatar
      language
      timezone
    }
    twoFactorEnabled
    createdAt
    updatedAt
  }
`

export const CLIENT_FRAGMENT = gql`
  fragment ClientFields on Client {
    id
    email
    uuid
    password
    flow
    limitIP
    totalGB
    expiryTime
    enable
    tgId
    subId
    reset
    createdAt
    updatedAt
  }
`

export const INBOUND_FRAGMENT = gql`
  fragment InboundFields on Inbound {
    id
    remark
    enable
    protocol
    settings
    streamSettings {
      network
      security
      tlsSettings
      realitySettings
      wsSettings
      grpcSettings
    }
    tag
    sniffing
    listen
    port
    createdAt
    updatedAt
  }
`

export const TRAFFIC_STATS_FRAGMENT = gql`
  fragment TrafficStatsFields on TrafficStats {
    clientId
    period
    upload
    download
    total
    points {
      time
      upload
      download
    }
  }
`

// Auth запросы
export const LOGIN_MUTATION = gql`
  mutation Login($input: LoginInput!) {
    login(input: $input) {
      user {
        ...UserFields
      }
      accessToken
      refreshToken
      expiresIn
    }
  }
  ${USER_FRAGMENT}
`

export const LOGOUT_MUTATION = gql`
  mutation Logout {
    logout
  }
`

export const ME_QUERY = gql`
  query Me {
    me {
      ...UserFields
    }
  }
  ${USER_FRAGMENT}
`

export const REFRESH_TOKEN_MUTATION = gql`
  mutation RefreshToken($token: String!) {
    refreshToken(token: $token) {
      accessToken
      refreshToken
      expiresIn
    }
  }
`

export const SETUP_2FA_MUTATION = gql`
  mutation Setup2FA {
    setup2FA {
      secret
      qrCode
      backupCodes
    }
  }
`

export const VERIFY_2FA_MUTATION = gql`
  mutation Verify2FA($code: String!) {
    verify2FA(code: $code)
  }
`

// User запросы
export const USERS_QUERY = gql`
  query Users($filter: UserFilter, $pagination: PaginationInput) {
    users(filter: $filter, pagination: $pagination) {
      nodes {
        ...UserFields
      }
      pageInfo {
        page
        limit
        total
        totalPages
        hasNext
        hasPrev
      }
    }
  }
  ${USER_FRAGMENT}
`

export const USER_QUERY = gql`
  query User($id: UUID!) {
    user(id: $id) {
      ...UserFields
      clients {
        ...ClientFields
      }
      subscription {
        id
        plan {
          name
          price
          interval
        }
        status
        currentPeriodEnd
      }
    }
  }
  ${USER_FRAGMENT}
  ${CLIENT_FRAGMENT}
`

export const CREATE_USER_MUTATION = gql`
  mutation CreateUser($input: CreateUserInput!) {
    createUser(input: $input) {
      ...UserFields
    }
  }
  ${USER_FRAGMENT}
`

export const UPDATE_USER_MUTATION = gql`
  mutation UpdateUser($id: UUID!, $input: UpdateUserInput!) {
    updateUser(id: $id, input: $input) {
      ...UserFields
    }
  }
  ${USER_FRAGMENT}
`

export const DELETE_USER_MUTATION = gql`
  mutation DeleteUser($id: UUID!) {
    deleteUser(id: $id)
  }
`

// Client запросы
export const CLIENTS_QUERY = gql`
  query Clients($filter: ClientFilter, $pagination: PaginationInput) {
    clients(filter: $filter, pagination: $pagination) {
      nodes {
        ...ClientFields
        user {
          username
          email
        }
        inbound {
          remark
          protocol
          port
        }
        trafficStats {
          total
          upload
          download
        }
      }
      pageInfo {
        page
        limit
        total
        totalPages
        hasNext
        hasPrev
      }
    }
  }
  ${CLIENT_FRAGMENT}
`

export const CLIENT_QUERY = gql`
  query Client($id: UUID!) {
    client(id: $id) {
      ...ClientFields
      user {
        ...UserFields
      }
      inbound {
        ...InboundFields
      }
      trafficStats {
        ...TrafficStatsFields
      }
      connectionLogs(pagination: { page: 1, limit: 10 }) {
        nodes {
          id
          ip
          country
          city
          userAgent
          connectedAt
          disconnectedAt
          duration
        }
      }
    }
  }
  ${CLIENT_FRAGMENT}
  ${USER_FRAGMENT}
  ${INBOUND_FRAGMENT}
  ${TRAFFIC_STATS_FRAGMENT}
`

export const CREATE_CLIENT_MUTATION = gql`
  mutation CreateClient($input: CreateClientInput!) {
    createClient(input: $input) {
      ...ClientFields
    }
  }
  ${CLIENT_FRAGMENT}
`

export const UPDATE_CLIENT_MUTATION = gql`
  mutation UpdateClient($id: UUID!, $input: UpdateClientInput!) {
    updateClient(id: $id, input: $input) {
      ...ClientFields
    }
  }
  ${CLIENT_FRAGMENT}
`

export const DELETE_CLIENT_MUTATION = gql`
  mutation DeleteClient($id: UUID!) {
    deleteClient(id: $id)
  }
`

export const RESET_CLIENT_TRAFFIC_MUTATION = gql`
  mutation ResetClientTraffic($id: UUID!) {
    resetClientTraffic(id: $id)
  }
`

// Inbound запросы
export const INBOUNDS_QUERY = gql`
  query Inbounds($filter: InboundFilter) {
    inbounds(filter: $filter) {
      ...InboundFields
      clients {
        id
        email
        enable
      }
      stats {
        download
        upload
        total
      }
    }
  }
  ${INBOUND_FRAGMENT}
`

export const INBOUND_QUERY = gql`
  query Inbound($id: UUID!) {
    inbound(id: $id) {
      ...InboundFields
      user {
        username
        email
      }
      clients {
        ...ClientFields
      }
      stats {
        download
        upload
        total
        recordedAt
      }
    }
  }
  ${INBOUND_FRAGMENT}
  ${CLIENT_FRAGMENT}
`

export const CREATE_INBOUND_MUTATION = gql`
  mutation CreateInbound($input: CreateInboundInput!) {
    createInbound(input: $input) {
      ...InboundFields
    }
  }
  ${INBOUND_FRAGMENT}
`

export const UPDATE_INBOUND_MUTATION = gql`
  mutation UpdateInbound($id: UUID!, $input: UpdateInboundInput!) {
    updateInbound(id: $id, input: $input) {
      ...InboundFields
    }
  }
  ${INBOUND_FRAGMENT}
`

export const DELETE_INBOUND_MUTATION = gql`
  mutation DeleteInbound($id: UUID!) {
    deleteInbound(id: $id)
  }
`

export const RESTART_INBOUND_MUTATION = gql`
  mutation RestartInbound($id: UUID!) {
    restartInbound(id: $id)
  }
`

// Analytics запросы
export const ANALYTICS_OVERVIEW_QUERY = gql`
  query AnalyticsOverview($period: TimePeriod!) {
    analytics(period: $period) {
      period
      systemMetrics {
        timestamp
        activeUsers
        activeConnections
        totalTraffic
        bandwidthUsage
        cpuUsage
        memoryUsage
        diskUsage
      }
      topUsers {
        clientId
        username
        traffic
        trend
      }
      trafficTrend {
        time
        value
        trend
      }
      anomalies {
        id
        clientId
        timestamp
        value
        type
        severity
        description
      }
      protocolDistribution {
        name
        value
      }
      usersTrend
      connectionsTrend
      trafficTrend
    }
  }
`

export const TRAFFIC_STATS_QUERY = gql`
  query TrafficStats($clientId: UUID, $period: TimePeriod!) {
    trafficStats(clientId: $clientId, period: $period) {
      ...TrafficStatsFields
    }
  }
  ${TRAFFIC_STATS_FRAGMENT}
`

export const PREDICTIONS_QUERY = gql`
  query Predictions($clientId: UUID!, $days: Int!) {
    predictions(clientId: $clientId, days: $days) {
      clientId
      days
      predictions {
        date
        traffic
        confidence
        upperBound
        lowerBound
      }
      confidence
    }
  }
`

export const ANOMALIES_QUERY = gql`
  query Anomalies($threshold: Float!) {
    anomalies(threshold: $threshold) {
      clientId
      timestamp
      value
      type
      severity
      description
    }
  }
`

// System запросы
export const SYSTEM_STATUS_QUERY = gql`
  query SystemStatus {
    systemStatus {
      version
      uptime
      services {
        name
        status
        uptime
        lastRestart
        errorCount
      }
      resources {
        cpu {
          model
          cores
          usage
        }
        memory {
          total
          available
          used
          usedPercent
        }
        disk {
          total
          free
          used
          usedPercent
        }
      }
    }
  }
`

export const HEALTH_CHECK_QUERY = gql`
  query HealthCheck {
    healthCheck {
      status
      checks {
        name
        status
        message
        lastCheck
      }
      timestamp
    }
  }
`

export const LOGS_QUERY = gql`
  query Logs($filter: LogFilter, $pagination: PaginationInput) {
    logs(filter: $filter, pagination: $pagination) {
      nodes {
        id
        level
        service
        message
        timestamp
        metadata
      }
      pageInfo {
        page
        limit
        total
        totalPages
        hasNext
        hasPrev
      }
    }
  }
`

// System мутации
export const RESTART_SERVICE_MUTATION = gql`
  mutation RestartService($service: ServiceType!) {
    restartService(service: $service)
  }
`

export const BACKUP_DATABASE_MUTATION = gql`
  mutation BackupDatabase {
    backupDatabase {
      id
      filename
      size
      createdAt
    }
  }
`

export const RESTORE_DATABASE_MUTATION = gql`
  mutation RestoreDatabase($backupId: String!) {
    restoreDatabase(backupId: $backupId)
  }
`

export const UPDATE_SETTINGS_MUTATION = gql`
  mutation UpdateSettings($input: SettingsInput!) {
    updateSettings(input: $input) {
      id
      key
      value
      updatedAt
    }
  }
`

// Подписки
export const SYSTEM_METRICS_SUBSCRIPTION = gql`
  subscription SystemMetrics {
    systemMetrics {
      timestamp
      activeUsers
      activeConnections
      totalTraffic
      bandwidthUsage
      cpuUsage
      memoryUsage
      diskUsage
    }
  }
`

export const USER_TRAFFIC_SUBSCRIPTION = gql`
  subscription UserTraffic($userId: UUID!) {
    userTraffic(userId: $userId) {
      userId
      upload
      download
      timestamp
    }
  }
`

export const CLIENT_TRAFFIC_SUBSCRIPTION = gql`
  subscription ClientTraffic($clientId: UUID!) {
    clientTraffic(clientId: $clientId) {
      clientId
      upload
      download
      timestamp
    }
  }
`

export const SERVER_STATUS_SUBSCRIPTION = gql`
  subscription ServerStatus($serverId: UUID!) {
    serverStatus(serverId: $serverId) {
      serverId
      status
      uptime
      connections
      cpuUsage
      memoryUsage
      timestamp
    }
  }
`

export const NOTIFICATIONS_SUBSCRIPTION = gql`
  subscription Notifications($userId: UUID!) {
    notifications(userId: $userId) {
      id
      userId
      type
      title
      message
      data
      read
      createdAt
    }
  }
`

export const LOG_STREAM_SUBSCRIPTION = gql`
  subscription LogStream($filter: LogFilter) {
    logStream(filter: $filter) {
      id
      level
      service
      message
      timestamp
      metadata
    }
  }
`