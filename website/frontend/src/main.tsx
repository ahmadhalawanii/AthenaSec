import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import './styles/athenasec.css'
import './styles/react-stability.css'
import './styles/integrations-table-fix.css'
import './styles/user-management-table-fix.css'

import App from './App.tsx'

const rootElement = document.getElementById('root')

if (!rootElement) {
  throw new Error('Root element was not found.')
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
)