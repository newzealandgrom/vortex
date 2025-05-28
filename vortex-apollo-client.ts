import { ApolloClient, InMemoryCache, createHttpLink, split, ApolloLink } from '@apollo/client'
import { setContext } from '@apollo/client/link/context'
import { onError } from '@apollo/client/link/error'
import { WebSocketLink } from '@apollo/client/link/ws'
import { getMainDefinition } from '@apollo/client/utilities'
import { getCookie } from '@/lib/cookies'
import toast from 'react-hot-toast'

// HTTP link для обычных запросов
const httpLink = createHttpLink({
  uri: process.env.NEXT_PUBLIC_GRAPHQL_URL || 'http://localhost:8080/graphql',
  credentials: 'include',
})

// WebSocket link для подписок
const wsLink = process.browser
  ? new WebSocketLink({
      uri: process.env.NEXT_PUBLIC_WS_URL?.replace('http', 'ws') + '/graphql' || 'ws://localhost:8080/graphql',
      options: {
        reconnect: true,
        lazy: true,
        connectionParams: async () => {
          const token = getCookie('access_token')
          return {
            authorization: token ? `Bearer ${token}` : '',
          }
        },
      },
    })
  : null

// Auth link для добавления токена к запросам
const authLink = setContext((_, { headers }) => {
  const token = getCookie('access_token')
  
  return {
    headers: {
      ...headers,
      authorization: token ? `Bearer ${token}` : '',
    },
  }
})

// Error link для обработки ошибок
const errorLink = onError(({ graphQLErrors, networkError, operation, forward }) => {
  if (graphQLErrors) {
    graphQLErrors.forEach(({ message, locations, path, extensions }) => {
      console.error(
        `[GraphQL error]: Message: ${message}, Location: ${locations}, Path: ${path}`
      )
      
      // Обработка специфичных ошибок
      if (extensions?.code === 'UNAUTHENTICATED') {
        // Перенаправление на страницу логина
        if (typeof window !== 'undefined') {
          window.location.href = '/auth/login'
        }
      } else if (extensions?.code === 'FORBIDDEN') {
        toast.error('У вас нет прав для выполнения этого действия')
      } else {
        toast.error(message)
      }
    })
  }

  if (networkError) {
    console.error(`[Network error]: ${networkError}`)
    
    if ('statusCode' in networkError) {
      if (networkError.statusCode === 401) {
        // Token expired, redirect to login
        if (typeof window !== 'undefined') {
          window.location.href = '/auth/login'
        }
      } else if (networkError.statusCode >= 500) {
        toast.error('Ошибка сервера. Пожалуйста, попробуйте позже.')
      }
    } else {
      toast.error('Ошибка сети. Проверьте подключение к интернету.')
    }
  }
})

// Split link для разделения между HTTP и WebSocket
const splitLink = process.browser && wsLink
  ? split(
      ({ query }) => {
        const definition = getMainDefinition(query)
        return (
          definition.kind === 'OperationDefinition' &&
          definition.operation === 'subscription'
        )
      },
      wsLink,
      authLink.concat(httpLink)
    )
  : authLink.concat(httpLink)

// Создание Apollo Client
export const apolloClient = new ApolloClient({
  link: ApolloLink.from([errorLink, splitLink]),
  cache: new InMemoryCache({
    typePolicies: {
      Query: {
        fields: {
          users: {
            keyArgs: ['filter'],
            merge(existing, incoming, { args }) {
              if (!args?.pagination?.page || args.pagination.page === 1) {
                return incoming
              }
              return {
                ...incoming,
                nodes: [...(existing?.nodes || []), ...incoming.nodes],
              }
            },
          },
          clients: {
            keyArgs: ['filter'],
            merge(existing, incoming, { args }) {
              if (!args?.pagination?.page || args.pagination.page === 1) {
                return incoming
              }
              return {
                ...incoming,
                nodes: [...(existing?.nodes || []), ...incoming.nodes],
              }
            },
          },
          notifications: {
            keyArgs: ['filter'],
            merge(existing, incoming, { args }) {
              if (!args?.pagination?.page || args.pagination.page === 1) {
                return incoming
              }
              return {
                ...incoming,
                nodes: [...(existing?.nodes || []), ...incoming.nodes],
              }
            },
          },
        },
      },
      User: {
        fields: {
          clients: {
            merge(existing = [], incoming) {
              return incoming
            },
          },
        },
      },
      Client: {
        fields: {
          trafficStats: {
            merge(existing, incoming) {
              return incoming
            },
          },
        },
      },
    },
    possibleTypes: {
      Node: ['User', 'Client', 'Inbound', 'Notification', 'Alert', 'Incident'],
    },
  }),
  defaultOptions: {
    watchQuery: {
      fetchPolicy: 'cache-and-network',
      errorPolicy: 'all',
    },
    query: {
      fetchPolicy: 'cache-first',
      errorPolicy: 'all',
    },
    mutate: {
      errorPolicy: 'all',
    },
  },
  connectToDevTools: process.env.NODE_ENV === 'development',
})

// Функция для очистки кэша
export const clearApolloCache = () => {
  apolloClient.clearStore()
}

// Функция для рефетча всех активных запросов
export const refetchQueries = () => {
  apolloClient.refetchQueries({
    include: 'active',
  })
}