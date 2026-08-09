export type UserRole = 'Analyst' | 'Administrator'
export type UserStatus = 'Active' | 'Suspended'
export type ModalMode =
  | 'add'
  | 'edit'
  | 'view'
  | 'delete'
  | 'reset-password'
  | null

export type UserRecord = {
  id: string
  name: string
  email: string
  role: UserRole
  status: UserStatus
  department: string
  phone: string
  mfaEnabled: boolean
  lastLogin: string
  createdAt: string
}

export type UserFormState = {
  name: string
  email: string
  role: UserRole
  status: UserStatus
  department: string
  phone: string
  mfaEnabled: boolean
}
