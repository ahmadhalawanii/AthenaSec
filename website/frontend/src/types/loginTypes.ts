import type { StatusTone } from '../utils/statusTone'

export type LoginPageProps = {
  onSignIn: (email: string, password: string) => boolean
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
