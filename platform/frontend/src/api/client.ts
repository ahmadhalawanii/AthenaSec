/*
  Talks to the AthenaSec backend (backend/app/main.py, routes under /api/v1).

  Requests go to the same origin: in development Vite forwards /api to the
  backend (vite.config.ts), in production the web server does. That keeps
  the session cookie first-party, which the backend requires
  (httpOnly, SameSite=Strict).

  Every change (POST, PUT) sends the CSRF token the backend gave at sign-in,
  in the X-AthenaSec-CSRF header.
*/

const API_BASE = ((import.meta.env.VITE_API_URL as string | undefined) ?? '').replace(/\/$/, '')
const TIMEOUT_MS = 8000

let csrfToken: string | null = null

export function setCsrfToken(token: string | null) {
  csrfToken = token
}

export class ApiError extends Error {
  // null when the backend could not be reached at all
  status: number | null

  constructor(status: number | null, message: string) {
    super(message)
    this.status = status
  }

  get unreachable() {
    return this.status === null
  }
}

type RequestOptions = {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  body?: unknown
}

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const headers: Record<string, string> = { Accept: 'application/json' }

  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }

  if (method !== 'GET' && csrfToken) {
    headers['X-AthenaSec-CSRF'] = csrfToken
  }

  const controller = new AbortController()
  const timer = window.setTimeout(() => controller.abort(), TIMEOUT_MS)
  let response: Response

  try {
    response = await fetch(`${API_BASE}/api/v1${path}`, {
      method,
      headers,
      credentials: 'include',
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: controller.signal,
    })
  } catch {
    throw new ApiError(null, 'The AthenaSec backend could not be reached.')
  } finally {
    window.clearTimeout(timer)
  }

  const text = await response.text()
  let data: unknown

  try {
    data = text ? JSON.parse(text) : null
  } catch {
    // Not JSON: a proxy error page, so the backend itself is not answering
    throw new ApiError(null, 'The AthenaSec backend could not be reached.')
  }

  if (!response.ok) {
    const detail = (data as { detail?: unknown } | null)?.detail

    // The backend always explains an error ({"detail": ...}). An empty 5xx
    // comes from the dev proxy or web server: the backend is not running.
    if (detail === undefined && response.status >= 500) {
      throw new ApiError(null, 'The AthenaSec backend could not be reached.')
    }
    const message =
      typeof detail === 'string'
        ? detail
        : Array.isArray(detail) && detail.length > 0 && detail.every((item) => typeof item === 'string')
          ? detail.join(' ')
          : Array.isArray(detail)
            ? 'The request was not valid.'
          : `Request failed (${response.status}).`

    throw new ApiError(response.status, message)
  }

  return data as T
}

// Reads every page of a list route ({ total, items, next_cursor })
export async function apiList<T>(path: string, maxItems = 1000): Promise<T[]> {
  const items: T[] = []
  let cursor: string | null = null
  const separator = path.includes('?') ? '&' : '?'

  do {
    const query: string = `${separator}limit=200${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`
    const page: { items: T[]; next_cursor: string | null } = await api(`${path}${query}`)

    items.push(...page.items)
    cursor = page.next_cursor
  } while (cursor && items.length < maxItems)

  return items
}
