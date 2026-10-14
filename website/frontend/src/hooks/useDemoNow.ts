import { useResponseState } from './useResponseState'

/*
  "Now" for every deadline and expiry on screen. It is the demo clock
  (starting at DEMO_NOW), not the real clock, so a request that is open
  in the demo data stays open however late the demo is run. Pages pass
  it to the pure helpers in policyEngine.ts (windowState, tokenState).
*/
export function useDemoNow() {
  return useResponseState().now
}
