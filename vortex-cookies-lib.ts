import Cookies from 'js-cookie'

interface CookieOptions {
  expires?: number | Date
  path?: string
  domain?: string
  secure?: boolean
  sameSite?: 'strict' | 'lax' | 'none'
}

// Установка cookie
export function setCookie(name: string, value: string, options?: CookieOptions) {
  const defaultOptions: CookieOptions = {
    path: '/',
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    ...options,
  }

  // Если expires указан как число, конвертируем в дату
  if (typeof defaultOptions.expires === 'number') {
    defaultOptions.expires = new Date(Date.now() + defaultOptions.expires * 60 * 1000)
  }

  Cookies.set(name, value, defaultOptions as Cookies.CookieAttributes)
}

// Получение cookie
export function getCookie(name: string): string | undefined {
  return Cookies.get(name)
}

// Удаление cookie
export function removeCookie(name: string, options?: Pick<CookieOptions, 'path' | 'domain'>) {
  const defaultOptions = {
    path: '/',
    ...options,
  }

  Cookies.remove(name, defaultOptions as Cookies.CookieAttributes)
}

// Получение всех cookies
export function getAllCookies(): { [key: string]: string } {
  return Cookies.get()
}

// Проверка наличия cookie
export function hasCookie(name: string): boolean {
  return getCookie(name) !== undefined
}

// Очистка всех cookies
export function clearAllCookies() {
  const cookies = getAllCookies()
  Object.keys(cookies).forEach((name) => {
    removeCookie(name)
  })
}

// Парсинг JSON из cookie
export function getJsonCookie<T>(name: string): T | null {
  const value = getCookie(name)
  if (!value) return null

  try {
    return JSON.parse(value) as T
  } catch {
    return null
  }
}

// Сохранение JSON в cookie
export function setJsonCookie<T>(name: string, value: T, options?: CookieOptions) {
  try {
    const jsonString = JSON.stringify(value)
    setCookie(name, jsonString, options)
  } catch (error) {
    console.error('Failed to stringify cookie value:', error)
  }
}

// Работа с secure cookies (только для production)
export function setSecureCookie(name: string, value: string, options?: CookieOptions) {
  setCookie(name, value, {
    ...options,
    secure: true,
    sameSite: 'strict',
  })
}

// Работа с HttpOnly cookies (только через API)
// Эти функции будут работать только на сервере
export function setHttpOnlyCookie(name: string, value: string, options?: CookieOptions) {
  if (typeof window !== 'undefined') {
    console.warn('HttpOnly cookies can only be set on the server')
    return
  }
  
  // Эта функция должна использоваться только в API routes
  // или server-side функциях
}

// Утилита для работы с токенами
export const tokenUtils = {
  setAccessToken: (token: string) => {
    setCookie('access_token', token, {
      expires: 15, // 15 минут
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    })
  },

  setRefreshToken: (token: string) => {
    setCookie('refresh_token', token, {
      expires: 7 * 24 * 60, // 7 дней
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    })
  },

  getAccessToken: () => getCookie('access_token'),
  getRefreshToken: () => getCookie('refresh_token'),

  clearTokens: () => {
    removeCookie('access_token')
    removeCookie('refresh_token')
  },

  isAuthenticated: () => {
    return !!getCookie('access_token')
  },
}

// Утилита для работы с настройками пользователя
export const userPrefsUtils = {
  setTheme: (theme: 'light' | 'dark' | 'system') => {
    setCookie('theme', theme, { expires: 365 })
  },

  getTheme: () => getCookie('theme') as 'light' | 'dark' | 'system' | undefined,

  setLocale: (locale: string) => {
    setCookie('locale', locale, { expires: 365 })
  },

  getLocale: () => getCookie('locale') || 'ru',
}

// Server-side cookie parser (для использования в middleware)
export function parseCookies(cookieString: string): { [key: string]: string } {
  const cookies: { [key: string]: string } = {}
  
  if (!cookieString) return cookies

  cookieString.split(';').forEach((cookie) => {
    const [name, value] = cookie.trim().split('=')
    if (name && value) {
      cookies[name] = decodeURIComponent(value)
    }
  })

  return cookies
}

// Cookie consent utilities
export const consentUtils = {
  hasConsent: () => getCookie('cookie_consent') === 'true',

  setConsent: (consent: boolean) => {
    setCookie('cookie_consent', consent.toString(), {
      expires: 365, // 1 год
      sameSite: 'lax',
    })
  },

  getConsentDetails: () => {
    return getJsonCookie<{
      analytics: boolean
      marketing: boolean
      functional: boolean
    }>('cookie_consent_details')
  },

  setConsentDetails: (details: {
    analytics: boolean
    marketing: boolean
    functional: boolean
  }) => {
    setJsonCookie('cookie_consent_details', details, { expires: 365 })
  },
}