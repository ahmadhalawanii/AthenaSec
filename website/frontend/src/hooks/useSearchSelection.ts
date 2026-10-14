import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

import type { SearchNavigationState } from '../types/searchTypes'

/*
  When the top-bar search (or a link from another page) opens this page
  for a record, select that record. `reveal` runs first so the page can
  clear any view or filter that would hide it. AppLayout then scrolls
  to the item and focuses it (items opt in with data-record-id).

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

  useEffect(() => {
    if (!target || !ids.includes(target)) {
      return
    }

    reveal?.(target)
    select(target)
    // Run once per navigation; ids and callbacks change on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.key, target])
}
