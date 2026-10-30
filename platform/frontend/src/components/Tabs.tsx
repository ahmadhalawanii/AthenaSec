import { useId, useRef, type KeyboardEvent, type ReactNode } from 'react'

type Tab<T extends string> = {
  value: T
  label: string
  // An optional status dot before the label (ok, caution, danger, neutral)...
  tone?: 'ok' | 'caution' | 'danger' | 'neutral'
  // ...and its meaning in words, read by screen readers so colour is never the only signal
  status?: string
}

type TabsProps<T extends string> = {
  label: string
  tabs: Tab<T>[]
  value: T
  onChange: (value: T) => void
  // The selected tab's panel
  children: ReactNode
}

/*
  A tablist following the ARIA tabs pattern: arrow keys, Home and End
  move between tabs (and select them); only the selected tab is in the
  Tab order; each tab controls the panel below it.
*/
function Tabs<T extends string>({ label, tabs, value, onChange, children }: TabsProps<T>) {
  const baseId = useId().replace(/[^a-zA-Z0-9_-]/g, '')
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([])
  const tabId = (tab: T) => `${baseId}-tab-${tab}`
  const panelId = `${baseId}-panel`

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const last = tabs.length - 1
    const next = {
      ArrowRight: index === last ? 0 : index + 1,
      ArrowLeft: index === 0 ? last : index - 1,
      Home: 0,
      End: last,
    }[event.key]

    if (next === undefined) {
      return
    }

    event.preventDefault()
    onChange(tabs[next].value)
    tabRefs.current[next]?.focus()
  }

  return (
    <div className="tabs">
      <div className="tab-list" role="tablist" aria-label={label}>
        {tabs.map((tab, index) => {
          const selected = tab.value === value
          return (
            <button
              key={tab.value}
              ref={(element) => {
                tabRefs.current[index] = element
              }}
              id={tabId(tab.value)}
              className="tab"
              type="button"
              role="tab"
              aria-selected={selected}
              aria-controls={panelId}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(tab.value)}
              onKeyDown={(event) => handleKeyDown(event, index)}
            >
              {tab.tone && <span className={`tab-dot ${tab.tone}`} aria-hidden="true" />}
              {tab.label}
              {tab.status && <span className="visually-hidden">, {tab.status}</span>}
            </button>
          )
        })}
      </div>

      <div className="tab-panel" id={panelId} role="tabpanel" aria-labelledby={tabId(value)} tabIndex={0}>
        {children}
      </div>
    </div>
  )
}

export default Tabs
