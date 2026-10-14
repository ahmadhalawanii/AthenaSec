import { useEffect, useRef, useState, type ReactNode } from 'react'

type TableScrollProps = {
  children: ReactNode
  label: string
}

type ScrollEdges = {
  left: boolean
  right: boolean
}

/*
  Wraps a table that may be wider than its card. While there are
  columns off to the right it shows a "scroll sideways" hint; once
  scrolled, the left edge fades. An overflowing table also becomes a
  focusable, labelled region so it can be scrolled from the keyboard.

  The inner element keeps the .table-scroll class, so all existing
  table CSS (pinned columns, page column widths) still applies.
*/
function TableScroll({ children, label }: TableScrollProps) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const [edges, setEdges] = useState<ScrollEdges>({
    left: false,
    right: false,
  })

  useEffect(() => {
    const scroller = scrollRef.current

    if (!scroller) {
      return
    }

    function update() {
      if (!scroller) {
        return
      }

      const maxScroll = scroller.scrollWidth - scroller.clientWidth
      const next = {
        left: scroller.scrollLeft > 1,
        right: maxScroll - scroller.scrollLeft > 1,
      }

      setEdges((previous) =>
        previous.left === next.left && previous.right === next.right
          ? previous
          : next,
      )
    }

    // ResizeObserver also fires once on observe, which sets the first state.
    const observer = new ResizeObserver(update)
    observer.observe(scroller)

    if (scroller.firstElementChild) {
      observer.observe(scroller.firstElementChild)
    }

    scroller.addEventListener('scroll', update, { passive: true })

    return () => {
      observer.disconnect()
      scroller.removeEventListener('scroll', update)
    }
  }, [])

  const overflowing = edges.left || edges.right

  const frameClass = [
    'table-scroll-frame',
    edges.left ? 'scrolled' : '',
    edges.right ? 'more-right' : '',
  ]
    .filter(Boolean)
    .join(' ')

  return (
    <div className={frameClass}>
      <div
        className="table-scroll"
        ref={scrollRef}
        role={overflowing ? 'region' : undefined}
        tabIndex={overflowing ? 0 : undefined}
        aria-label={
          overflowing ? `${label} (scrolls sideways)` : undefined
        }
      >
        {children}
      </div>

      {edges.right && (
        <p className="table-scroll-hint" aria-hidden="true">
          Scroll sideways for more columns →
        </p>
      )}
    </div>
  )
}

export default TableScroll
