import { createContext, type MutableRefObject } from 'react'

import type { ResponsePolicy } from '../types/responsePoliciesTypes'

export type ResponsePolicyStore = {
  policy: ResponsePolicy
  // The policy as of the latest save, for handlers that must not read a stale copy
  policyRef: MutableRefObject<ResponsePolicy>
  // Storing a saved policy also ends any draft
  setPolicy: (next: ResponsePolicy) => void
  // The Permissions draft (null when nothing has been edited). It lives here, above the routes, so it
  // survives a change of tab or page; it is cleared on Save, Discard, sign-out and a change of user.
  draft: ResponsePolicy | null
  editDraft: (change: (next: ResponsePolicy) => void) => void
  discardDraft: () => void
  // For a reload the person has just confirmed (Reset demo): skips the browser's "leave this page?" prompt
  allowLeaving: () => void
  // How many changes the draft holds against the saved policy (0 when there is none)
  unsavedChanges: number
}

// Provided by ResponsePolicyProvider (above the approval flow); read with useResponsePolicy().
export const ResponsePolicyContext = createContext<ResponsePolicyStore | null>(null)
