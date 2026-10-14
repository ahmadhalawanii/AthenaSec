import { useContext } from 'react'

import { ResponseContext } from './responseContext'

/*
  The approval flow: requests and their decisions, tokens, what has run
  and is running, the demo clock, and the actions that change them.
  The alerts, dashboard, Incident Response, audit log and search all
  read from here (through the analyst and admin state) so they agree.
*/
export function useResponseState() {
  const state = useContext(ResponseContext)

  if (!state) {
    throw new Error('useResponseState must be used inside ResponseStateProvider')
  }

  return state
}
