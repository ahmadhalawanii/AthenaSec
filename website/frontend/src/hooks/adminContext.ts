import { createContext } from 'react'

import type { AdminState } from '../types/adminStateTypes'

// Provided by AdminStateProvider (inside AppLayout); read with useAdminState().
export const AdminContext = createContext<AdminState | null>(null)
