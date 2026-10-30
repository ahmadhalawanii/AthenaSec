import { useSyncExternalStore } from 'react'

/*
  True while the media query matches, updating on resize. Used where a
  layout changes what is rendered, not just how it looks (the attack
  map becomes a list on phones; detail panels become drawers).
*/
export function useMediaQuery(query: string) {
  return useSyncExternalStore(
    (onChange) => {
      const list = window.matchMedia(query)
      list.addEventListener('change', onChange)
      return () => list.removeEventListener('change', onChange)
    },
    () => window.matchMedia(query).matches,
  )
}

// The app's phone breakpoint (matches the 820px rules in athenasec.css)
export const PHONE_QUERY = '(max-width: 820px)'
