import { useContext } from 'react'

import { ResponsePolicyContext } from './responsePolicyContext'

/*
  The response policy as it stands now. The approval flow, Simulate an
  attempt, the alert assessments and the Response Policies page all read
  it from here, so a saved change reaches every one of them at once.
*/
export function useResponsePolicy() {
  const store = useContext(ResponsePolicyContext)

  if (!store) {
    throw new Error('useResponsePolicy must be used inside ResponsePolicyProvider')
  }

  return store
}
