export type Role = 'Analyst' | 'Administrator'

export type AppView = 'login' | 'mfa' | 'app'

export type DemoAccount = {
  email: string
  password: string
  role: Role
  name: string
}

export type AuthenticatedUser = {
  email: string
  role: Role
  name: string
}
