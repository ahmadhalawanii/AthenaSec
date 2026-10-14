import type { Role } from './appTypes'

export type MfaPageProps = {
  onVerify: () => void
  // The account waiting for its second factor (pendingUser in App.tsx)
  accountEmail: string
  accountRole: Role
}
