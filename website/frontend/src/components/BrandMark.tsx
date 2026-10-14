import { useId } from 'react'

type BrandMarkProps = {
  size?: number
}

// AthenaSec shield. Decorative: the wordmark beside it carries the name.
function BrandMark({ size = 30 }: BrandMarkProps) {
  // Each instance needs its own gradient id. useId() can contain
  // characters that url(#...) doesn't accept, so keep the safe ones.
  const gradientId = `brand-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`

  return (
    <svg
      className="brand-mark"
      width={size}
      height={size}
      viewBox="0 0 32 32"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#F0384F" />
          <stop offset="1" stopColor="#A3122A" />
        </linearGradient>
      </defs>
      <path
        d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7L16 2z"
        fill={`url(#${gradientId})`}
      />
      <path
        d="M16 9.5 10.8 22h2.9l1-2.6h2.6l1 2.6h2.9L16 9.5zm-.5 7.6.5-1.4.5 1.4h-1z"
        fill="#FFFFFF"
      />
    </svg>
  )
}

export default BrandMark
