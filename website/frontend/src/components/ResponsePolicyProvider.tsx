import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import { initialResponsePolicy } from '../data/responsePoliciesData'
import { listChanges } from '../data/policyEngine'
import { ResponsePolicyContext } from '../hooks/responsePolicyContext'
import type { ResponsePolicy } from '../types/responsePoliciesTypes'

/*
  Holds the one response policy for the session. It sits above the approval
  flow (ResponseStateProvider) so the flow can read it; the administrator's
  saves go through AdminStateProvider, which audits them and then stores
  the new policy here. Resets when the page reloads.

  It also holds the Permissions draft, so unsaved edits survive a change of tab
  or page (BrowserRouter has no way to ask "leave this page?" on an in-app click,
  so the draft is kept and shown instead; see DESIGN-SPEC). The draft is cleared
  on Save, on Discard, and whenever the signed-in person changes (sign-out, or
  signing in as someone else), so it never carries over to another user. While it
  holds changes, closing or reloading the tab asks first.
*/
function ResponsePolicyProvider({ children, userKey }: { children: ReactNode; userKey: string | null }) {
  const [policy, setState] = useState<ResponsePolicy>(initialResponsePolicy)
  const policyRef = useRef<ResponsePolicy>(initialResponsePolicy)
  const [draft, setDraft] = useState<ResponsePolicy | null>(null)

  // A different person (or nobody) starts without the last person's draft
  const [seenUser, setSeenUser] = useState(userKey)

  if (seenUser !== userKey) {
    setSeenUser(userKey)
    setDraft(null)
  }

  const setPolicy = useCallback((next: ResponsePolicy) => {
    policyRef.current = next
    setState(next)
    setDraft(null)
  }, [])

  const editDraft = useCallback((change: (next: ResponsePolicy) => void) => {
    setDraft((current) => {
      const next = structuredClone(current ?? policyRef.current)

      change(next)

      return next
    })
  }, [])

  const discardDraft = useCallback(() => setDraft(null), [])

  const leaving = useRef(false)
  const allowLeaving = useCallback(() => {
    leaving.current = true
  }, [])

  const unsavedChanges = draft ? listChanges(policy, draft).length : 0

  // Closing or reloading the tab asks first, only while there is something to lose
  useEffect(() => {
    if (unsavedChanges === 0) {
      return undefined
    }

    function warn(event: BeforeUnloadEvent) {
      if (leaving.current) {
        return
      }

      event.preventDefault()
      event.returnValue = ''
    }

    window.addEventListener('beforeunload', warn)

    return () => window.removeEventListener('beforeunload', warn)
  }, [unsavedChanges])

  const value = useMemo(
    () => ({ policy, policyRef, setPolicy, draft, editDraft, discardDraft, allowLeaving, unsavedChanges }),
    [policy, setPolicy, draft, editDraft, discardDraft, allowLeaving, unsavedChanges],
  )

  return <ResponsePolicyContext.Provider value={value}>{children}</ResponsePolicyContext.Provider>
}

export default ResponsePolicyProvider
