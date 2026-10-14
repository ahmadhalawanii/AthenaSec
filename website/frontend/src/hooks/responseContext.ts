import { createContext } from 'react'

import type { ResponseState } from '../types/responseStateTypes'

// Provided by ResponseStateProvider (above the routes); read with useResponseState().
export const ResponseContext = createContext<ResponseState | null>(null)
