import { useContext } from 'react'

import { AdminContext } from './adminContext'

/*
  The admin workspace's current policies, users,
  services, configuration and audit log (seed data plus this session's
  changes) and the actions that change them. Admin pages, the dashboard,
  search, the top bar and the sidebar read from here so they agree.
*/
export function useAdminState() {
  const state = useContext(AdminContext)

  if (!state) {
    throw new Error('useAdminState must be used inside AdminStateProvider')
  }

  return state
}
