import type { ReactNode } from 'react'
import { createPortal } from 'react-dom'

import { useDialog } from '../hooks/useDialog'
import { PHONE_QUERY, useMediaQuery } from '../hooks/useMediaQuery'

type ResponsiveDetailProps = {
  // Phones only: whether the drawer is open
  open: boolean
  onClose: () => void
  // id of the heading inside children that names the panel
  labelledBy: string
  // Accessible name for the drawer's close button
  closeLabel: string
  className?: string
  children: ReactNode
}

/*
  The selected item's details: an inline panel beside the list on wide
  screens, the shared useDialog drawer on phones (focus trap, Escape,
  focus back to the item that opened it).
*/
function ResponsiveDetail({
  open,
  onClose,
  labelledBy,
  closeLabel,
  className = '',
  children,
}: ResponsiveDetailProps) {
  const isPhone = useMediaQuery(PHONE_QUERY)
  const dialogRef = useDialog(onClose)

  if (!isPhone) {
    return (
      <section className={`card key detail-panel ${className}`} aria-labelledby={labelledBy}>
        {children}
      </section>
    )
  }

  if (!open) {
    return null
  }

  return createPortal(
    <div className="drawer-backdrop" role="presentation" onClick={onClose}>
      <aside
        ref={dialogRef}
        className={`alert-drawer detail-drawer ${className}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="detail-drawer-bar">
          <button className="icon-btn" type="button" aria-label={closeLabel} onClick={onClose}>
            <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="detail-drawer-body">{children}</div>
      </aside>
    </div>,
    document.body,
  )
}

export default ResponsiveDetail
