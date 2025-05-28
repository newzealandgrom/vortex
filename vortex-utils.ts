import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { format, formatDistance, formatRelative, isValid, parseISO } from 'date-fns'
import { ru, enUS } from 'date-fns/locale'

// Объединение классов Tailwind с поддержкой условий
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// Форматирование байтов в читаемый вид
export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 Bytes'

  const k = 1024
  const dm = decimals < 0 ? 0 : decimals
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']

  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]
}

// Форматирование скорости (байты в секунду)
export function formatSpeed(bytesPerSecond: number): string {
  return formatBytes(bytesPerSecond) + '/s'
}

// Форматирование процентов
export function formatPercent(value: number, decimals = 1): string {
  return `${value.toFixed(decimals)}%`
}

// Форматирование чисел с разделителями
export function formatNumber(num: number): string {
  return new Intl.NumberFormat('ru-RU').format(num)
}

// Форматирование даты
export function formatDate(date: Date | string | number, formatStr = 'PPpp', locale: 'ru' | 'en' = 'ru'): string {
  const dateObj = typeof date === 'string' ? parseISO(date) : new Date(date)
  
  if (!isValid(dateObj)) {
    return 'Invalid date'
  }
  
  const localeObj = locale === 'ru' ? ru : enUS
  return format(dateObj, formatStr, { locale: localeObj })
}

// Форматирование относительного времени
export function formatRelativeTime(date: Date | string | number, locale: 'ru' | 'en' = 'ru'): string {
  const dateObj = typeof date === 'string' ? parseISO(date) : new Date(date)
  
  if (!isValid(dateObj)) {
    return 'Invalid date'
  }
  
  const localeObj = locale === 'ru' ? ru : enUS
  return formatDistance(dateObj, new Date(), { addSuffix: true, locale: localeObj })
}

// Генерация случайного ID
export function generateId(length = 8): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let result = ''
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

// Генерация UUID v4
export function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}

// Копирование в буфер обмена
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    // Fallback для старых браузеров
    const textArea = document.createElement('textarea')
    textArea.value = text
    textArea.style.position = 'fixed'
    textArea.style.left = '-999999px'
    document.body.appendChild(textArea)
    textArea.focus()
    textArea.select()

    try {
      document.execCommand('copy')
      document.body.removeChild(textArea)
      return true
    } catch {
      document.body.removeChild(textArea)
      return false
    }
  }
}

// Debounce функция
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null

  return function executedFunction(...args: Parameters<T>) {
    const later = () => {
      timeout = null
      func(...args)
    }

    if (timeout) {
      clearTimeout(timeout)
    }
    timeout = setTimeout(later, wait)
  }
}

// Throttle функция
export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean = false

  return function executedFunction(...args: Parameters<T>) {
    if (!inThrottle) {
      func(...args)
      inThrottle = true
      setTimeout(() => inThrottle = false, limit)
    }
  }
}

// Проверка, является ли значение пустым
export function isEmpty(value: any): boolean {
  if (value == null) return true
  if (typeof value === 'string') return value.trim().length === 0
  if (Array.isArray(value)) return value.length === 0
  if (typeof value === 'object') return Object.keys(value).length === 0
  return false
}

// Глубокое сравнение объектов
export function deepEqual(obj1: any, obj2: any): boolean {
  if (obj1 === obj2) return true
  
  if (obj1 == null || obj2 == null) return false
  if (typeof obj1 !== typeof obj2) return false
  
  if (typeof obj1 !== 'object') return obj1 === obj2
  
  const keys1 = Object.keys(obj1)
  const keys2 = Object.keys(obj2)
  
  if (keys1.length !== keys2.length) return false
  
  for (const key of keys1) {
    if (!keys2.includes(key)) return false
    if (!deepEqual(obj1[key], obj2[key])) return false
  }
  
  return true
}

// Группировка массива по ключу
export function groupBy<T>(array: T[], key: keyof T): Record<string, T[]> {
  return array.reduce((result, item) => {
    const group = String(item[key])
    if (!result[group]) result[group] = []
    result[group].push(item)
    return result
  }, {} as Record<string, T[]>)
}

// Сортировка массива объектов
export function sortBy<T>(array: T[], key: keyof T, order: 'asc' | 'desc' = 'asc'): T[] {
  return [...array].sort((a, b) => {
    const aVal = a[key]
    const bVal = b[key]
    
    if (aVal < bVal) return order === 'asc' ? -1 : 1
    if (aVal > bVal) return order === 'asc' ? 1 : -1
    return 0
  })
}

// Пагинация массива
export function paginate<T>(array: T[], page: number, limit: number): {
  data: T[]
  total: number
  totalPages: number
  currentPage: number
  hasNext: boolean
  hasPrev: boolean
} {
  const total = array.length
  const totalPages = Math.ceil(total / limit)
  const currentPage = Math.max(1, Math.min(page, totalPages))
  const start = (currentPage - 1) * limit
  const end = start + limit

  return {
    data: array.slice(start, end),
    total,
    totalPages,
    currentPage,
    hasNext: currentPage < totalPages,
    hasPrev: currentPage > 1,
  }
}

// Форматирование ошибок
export function formatError(error: any): string {
  if (typeof error === 'string') return error
  if (error?.message) return error.message
  if (error?.response?.data?.message) return error.response.data.message
  if (error?.response?.data?.error) return error.response.data.error
  return 'An unknown error occurred'
}

// Валидация email
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

// Валидация URL
export function isValidUrl(url: string): boolean {
  try {
    new URL(url)
    return true
  } catch {
    return false
  }
}

// Генерация цвета по строке (для аватаров)
export function stringToColor(str: string): string {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash)
  }
  
  const hue = hash % 360
  return `hsl(${hue}, 70%, 50%)`
}

// Получение инициалов из имени
export function getInitials(name: string): string {
  return name
    .split(' ')
    .map(part => part[0])
    .join('')
    .toUpperCase()
    .slice(0, 2)
}

// Форматирование времени работы (uptime)
export function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  
  const parts = []
  if (days > 0) parts.push(`${days}d`)
  if (hours > 0) parts.push(`${hours}h`)
  if (minutes > 0) parts.push(`${minutes}m`)
  
  return parts.join(' ') || '0m'
}

// Безопасный парсинг JSON
export function safeJsonParse<T>(json: string, fallback: T): T {
  try {
    return JSON.parse(json)
  } catch {
    return fallback
  }
}

// Интерполяция строк с переменными
export function interpolate(template: string, variables: Record<string, any>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
    return variables[key] !== undefined ? String(variables[key]) : match
  })
}

// Задержка (для async/await)
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// Retry функция для промисов
export async function retry<T>(
  fn: () => Promise<T>,
  attempts = 3,
  delay = 1000,
  backoff = 2
): Promise<T> {
  try {
    return await fn()
  } catch (error) {
    if (attempts <= 1) throw error
    await sleep(delay)
    return retry(fn, attempts - 1, delay * backoff, backoff)
  }
}

// Маскирование строки (для паролей, токенов)
export function maskString(str: string, visibleStart = 4, visibleEnd = 4): string {
  if (str.length <= visibleStart + visibleEnd) return str
  
  const start = str.slice(0, visibleStart)
  const end = str.slice(-visibleEnd)
  const masked = '*'.repeat(str.length - visibleStart - visibleEnd)
  
  return `${start}${masked}${end}`
}

// Проверка темной темы
export function isDarkMode(): boolean {
  if (typeof window === 'undefined') return false
  
  return (
    document.documentElement.classList.contains('dark') ||
    (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)
  )
}

// Экспорт типов
export type { ClassValue }