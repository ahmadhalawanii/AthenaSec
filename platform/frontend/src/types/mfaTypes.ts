import type { Role } from './appTypes'

export type MfaPageProps = {
  // Resolves to an error message, or null once the user is signed in
  onVerify: (code: string) => Promise<string | null>
  // The account waiting for its second factor (pendingUser in App.tsx)
  accountEmail: string
  // Known only in demo mode; the backend reveals the role after the second factor
  accountRole: Role | null
  demoMode: boolean
}
