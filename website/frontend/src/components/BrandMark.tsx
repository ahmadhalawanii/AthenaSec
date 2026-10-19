type BrandMarkProps = {
  size?: number
}

// AthenaSec's supplied silver brand mark. Decorative: the adjacent wordmark carries the name.
function BrandMark({ size = 30 }: BrandMarkProps) {
  return (
    <img
      className="brand-mark"
      src="/athenasec-logo.png"
      width={size}
      height={size}
      alt=""
      aria-hidden="true"
      draggable={false}
    />
  )
}

export default BrandMark
