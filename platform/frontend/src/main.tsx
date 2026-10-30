import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

// Self-hosted Manrope for UI and headings; IBM Plex Mono for technical identifiers.
import '@fontsource-variable/manrope/wght.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'

import './styles/athenasec.css'
import './styles/react-stability.css'
import './styles/user-management-table-fix.css'

import App from './App.tsx'

const rootElement = document.getElementById('root')

if (!rootElement) {
  throw new Error('Root element was not found.')
}

createRoot(rootElement).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)