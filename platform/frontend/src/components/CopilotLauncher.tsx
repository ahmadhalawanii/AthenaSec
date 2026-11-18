import { useEffect, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'

import { useLiveData } from '../api/liveDataContext'

import CopilotChat from './CopilotChat'

type CopilotLauncherProps = {
  role: 'Analyst' | 'Administrator'
  // Set while the phone menu covers the page, like the rest of the page
  inert?: boolean
}

/*
  A floating button on every page that opens the Security Copilot in a panel. The panel stays
  mounted once opened (just hidden), so the conversation survives closing it and moving between
  pages. It is not modal: the page behind stays usable. On the Copilot page itself it is hidden,
  since the page already is the chat.
*/
function CopilotLauncher({ role, inert }: CopilotLauncherProps) {
  const { pathname } = useLocation()
  const live = useLiveData().mode === 'live'
  const [open, setOpen] = useState(false)
  const [everOpened, setEverOpened] = useState(false)
  const [focusSignal, setFocusSignal] = useState(0)
  const launcher = useRef<HTMLButtonElement>(null)

  function toggle() {
    const next = !open

    setOpen(next)

    if (next) {
      setEverOpened(true)
      setFocusSignal((count) => count + 1)
    }
  }

  useEffect(() => {
    if (!open) {
      return undefined
    }

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setOpen(false)
        launcher.current?.focus()
      }
    }

    window.addEventListener('keydown', onKeyDown)

    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open])

  if (pathname === '/app/copilot') {
    return null
  }

  return (
    <div className="copilot-launcher" inert={inert}>
      {everOpened && (
        <div
          id="copilot-panel"
          className="copilot-panel"
          role="dialog"
          aria-label="Security Copilot"
          hidden={!open}
        >
          <div className="copilot-panel-head">
            <strong>Security Copilot</strong>
            <button
              type="button"
              className="btn small ghost"
              onClick={() => {
                setOpen(false)
                launcher.current?.focus()
              }}
            >
              Close
            </button>
          </div>

          <CopilotChat role={role} live={live} compact focusSignal={focusSignal} />
        </div>
      )}

      <button
        ref={launcher}
        type="button"
        className="btn primary copilot-fab"
        aria-expanded={open}
        aria-controls="copilot-panel"
        onClick={toggle}
      >
        {open ? 'Close Copilot' : 'Ask Copilot'}
      </button>
    </div>
  )
}

export default CopilotLauncher
