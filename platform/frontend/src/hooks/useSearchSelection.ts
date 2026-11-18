import { useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'

import type { SearchNavigationState } from '../types/searchTypes'

/*
  When the top-bar search (or a link from another page) opens this page
  for a record, select that record. `reveal` runs first so the page can
  clear any view or filter that would hide it. AppLayout then scrolls
  to the item and focuses it (items opt in with data-record-id).

  In live mode the page's records may still be loading when the link
  lands, so the selection waits until the record is in `ids`, then
  happens once for that navigation.

  Selection only: on phones it does not open the detail drawer, so
  focus lands on the item in the list.
*/
export function useSearchSelection(
  ids: string[],
  select: (id: string) => void,
  reveal?: (id: string) => void,
) {
  const location = useLocation()
  const target = (location.state as SearchNavigationState | null)?.highlight
  const ready = Boolean(target && ids.includes(target))
  // The navigation (location.key) whose record was already selected
  const handled = useRef<string | null>(null)

  useEffect(() => {
    if (!target || !ready || handled.current === location.key) {
      return
    }

    handled.current = location.key
    reveal?.(target)
    select(target)
    // Run once per navigation, as soon as its record has loaded; the
    // callbacks change on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.key, target, ready])
}
