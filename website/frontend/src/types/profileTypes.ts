export type UserRole = 'Analyst' | 'Administrator'
export type ProfileState = 'Saved' | 'Draft' | 'Error'

export type ProfileValues = {
  displayName: string
  email: string
  department: string
  phone: string
  timezone: string
}

export type ProfilePageProps = {
  userName?: string
  userEmail?: string
  role?: UserRole
}
