import type { SegmentedOption } from '../types/uiTypes'

type SegmentedProps<T extends string> = {
  label: string
  options: SegmentedOption<T>[]
  value: T
  onChange: (value: T) => void
}

function Segmented<T extends string>({
  label,
  options,
  value,
  onChange,
}: SegmentedProps<T>) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className="segmented-option"
          aria-pressed={option.value === value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
          {/* The space keeps the accessible name "Needs decision 3", not "decision3" */}
          {option.count !== undefined && (
            <>
              {' '}
              <span className="segmented-count">{option.count}</span>
            </>
          )}
        </button>
      ))}
    </div>
  )
}

export default Segmented
