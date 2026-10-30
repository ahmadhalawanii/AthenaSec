import type { StatusTone } from '../utils/statusTone'

export type LoginPageProps = {
  // Resolves to an error message, or null when the second factor comes next
  onSignIn: (email: string, password: string, remember: boolean) => Promise<string | null>
  // Demo mode shows the sample accounts; live mode signs in against the backend
  demoMode: boolean
}

export type LoginStat = {
  value: string
  label: string
}

export type RadarBlip = {
  id: string
  x: number
  y: number
  tone: StatusTone
  // Open alerts pulse on the radar
  open: boolean
}
