import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useLocation } from 'react-router-dom'

import { useMediaQuery } from '../hooks/useMediaQuery'
import type { SearchNavigationState } from '../types/searchTypes'

import AdminStateProvider from './AdminStateProvider'
import LiveNotice from './LiveNotice'
import Sidebar from './Sidebar'
import SocStateProvider from './SocStateProvider'
import TopBar from './TopBar'

const HIGHLIGHT_MS = 2800

/*
  When the top-bar search opens a page it passes the record id in
  router state. Scroll that record into view, highlight it briefly, and
  move focus to it (or its first button) so keyboard users land on it.
  Records opt in with data-record-id; pages select it themselves with
  useSearchSelection.
*/
function useSearchHighlight() {
  const location = useLocation()
  const highlightId = (location.state as SearchNavigationState | null)
    ?.highlight

  useEffect(() => {
    if (!highlightId) {
      return
    }

    let row: Element | null = null
    let clearTimer = 0

    // Wait a frame so the page has rendered its rows.
    const findTimer = window.setTimeout(() => {
      row = document.querySelector(
        `[data-record-id="${CSS.escape(highlightId)}"]`,
      )

      if (!row) {
        return
      }

      row.scrollIntoView({ block: 'center' })
      row.classList.add('is-highlighted')

      // List items are buttons themselves; table rows focus their first button
      const focusTarget =
        row instanceof HTMLButtonElement
          ? row
          : row.querySelector<HTMLElement>('button')
      focusTarget?.focus({ preventScroll: true })

      clearTimer = window.setTimeout(
        () => row?.classList.remove('is-highlighted'),
        HIGHLIGHT_MS,
      )
    }, 50)

    return () => {
      window.clearTimeout(findTimer)
      window.clearTimeout(clearTimer)
      row?.classList.remove('is-highlighted')
    }
  }, [location.key, highlightId])
}

type AppLayoutProps = {
  children: ReactNode
  role: 'Analyst' | 'Administrator'
  userName: string
  userEmail: string
  onLogout: () => void
}

function AppLayout({
  children,
  role,
  userName,
  userEmail,
  onLogout,
}: AppLayoutProps) {
  useSearchHighlight()

  /*
    The phone menu drawer. Its state lives here so the hamburger can be the
    first control in the page (it is fixed over the header's left corner, so
    it looks the same wherever it sits in the DOM) and Tab follows the screen.
    While the drawer is open and covering the page (1024px and below) the
    top bar and the page are inert: Tab and clicks stay in the drawer and its
    hamburger, and closing it puts focus back on the hamburger.
  */
  const [navOpen, setNavOpen] = useState(false)
  const toggleRef = useRef<HTMLButtonElement>(null)
  const mainRef = useRef<HTMLElement>(null)
  const drawerMode = useMediaQuery('(max-width: 1024px)')
  const pageLocked = navOpen && drawerMode

  function closeNav(returnFocus = false) {
    setNavOpen(false)

    if (returnFocus) {
      toggleRef.current?.focus()
    }
  }

  useEffect(() => {
    if (!navOpen) {
      return undefined
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setNavOpen(false)
        toggleRef.current?.focus()
      }
    }

    window.addEventListener('keydown', handleKeyDown)

    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [navOpen])

  return (
    // Shared analyst and admin state live here so they survive moving between pages.
    <AdminStateProvider user={{ name: userName, email: userEmail, role }}>
      <SocStateProvider currentUser={userName}>
        <section className="section">
          {/* The first Tab stop: hidden until it has focus, then jumps past the header and menu */}
          <a
            className="skip-link"
            href="#main"
            inert={pageLocked}
            onClick={(event) => {
              event.preventDefault()
              mainRef.current?.focus()
            }}
          >
            Skip to main content
          </a>

          <div className="label">
            <span>AthenaSec High Fidelity</span>

            <span className="prototype-note">
              {role} Workspace
            </span>
          </div>

          <div className="screen">
            {/* Hamburger menu (hidden above 1024px, where the sidebar is always visible) */}
            <button
              ref={toggleRef}
              className={navOpen ? 'sidebar-toggle is-open' : 'sidebar-toggle'}
              type="button"
              onClick={() => setNavOpen(!navOpen)}
              aria-label={navOpen ? 'Close navigation menu' : 'Open navigation menu'}
              aria-expanded={navOpen}
              aria-controls="app-sidebar"
            >
              <span></span>
              <span></span>
              <span></span>
            </button>

            <TopBar
              userName={userName}
              role={role}
              onLogout={onLogout}
              inert={pageLocked}
            />

            <div className="body">
              <Sidebar
                role={role}
                onLogout={onLogout}
                open={navOpen}
                onClose={closeNav}
              />

              <main id="main" className="main" tabIndex={-1} ref={mainRef} inert={pageLocked}>
                {children}
              </main>
              <LiveNotice />
            </div>
          </div>
        </section>
      </SocStateProvider>
    </AdminStateProvider>
  )
}

export default AppLayout