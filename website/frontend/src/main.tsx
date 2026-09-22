import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

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
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)