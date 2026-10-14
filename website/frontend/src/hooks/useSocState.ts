import { useContext } from 'react'

import { SocContext } from './socContext'

/*
  The analyst workspace's current alerts and response runs (seed data
  plus this session's changes) and the actions that change them. Every
  page, the top bar and the sidebar read from here so they agree.
*/
export function useSocState() {
  const state = useContext(SocContext)

  if (!state) {
    throw new Error('useSocState must be used inside SocStateProvider')
  }

  return state
}
