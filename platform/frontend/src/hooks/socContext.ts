import { createContext } from 'react'

import type { SocState } from '../types/socTypes'

// Provided by SocStateProvider (inside AppLayout); read with useSocState().
export const SocContext = createContext<SocState | null>(null)
