import { useId } from 'react'

type SwitchProps = {
  checked: boolean
  onChange: (checked: boolean) => void
  label: string
  // Names what the switch controls when the visible label is only its state
  // ("Brute Force SSH rule" beside "Enabled"); the state comes from aria-checked
  accessibleName?: string
  disabled?: boolean
}

function Switch({ checked, onChange, label, accessibleName, disabled = false }: SwitchProps) {
  const labelId = useId()

  return (
    <span className="switch-field">
      <button
        type="button"
        className="switch"
        role="switch"
        aria-checked={checked}
        aria-label={accessibleName}
        aria-labelledby={accessibleName ? undefined : labelId}
        disabled={disabled}
        onClick={() => onChange(!checked)}
      >
        <span className="switch-thumb" aria-hidden="true" />
      </button>
      <span className="switch-label" id={labelId}>
        {label}
      </span>
    </span>
  )
}

export default Switch
