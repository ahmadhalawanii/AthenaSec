import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react'
import { createPortal } from 'react-dom'

export type OverflowMenuItem = {
  label: string
  onSelect: () => void
  disabled?: boolean
  destructive?: boolean
}

type OverflowMenuProps = {
  /* Accessible name for the "⋯" button, e.g. "More actions for Analyst A" */
  label: string
  items: OverflowMenuItem[]
  /* Shown under the items when any of them is disabled */
  disabledReason?: string
  className?: string
}

const GAP = 6
const EDGE = 8

type MenuPosition = { top: number; left: number }

/*
  Under the trigger, right-aligned to it, kept inside the viewport;
  above it when there's no room below. Null once the trigger has
  scrolled out of view.
*/
function computePosition(
  triggerElement: HTMLElement,
  menuElement: HTMLElement,
): MenuPosition | null {
  const trigger = triggerElement.getBoundingClientRect()
  const menu = menuElement.getBoundingClientRect()
  const viewportWidth = document.documentElement.clientWidth
  const viewportHeight = window.innerHeight

  if (trigger.bottom < 0 || trigger.top > viewportHeight) {
    return null
  }

  const fitsBelow =
    trigger.bottom + GAP + menu.height <= viewportHeight - EDGE

  return {
    top: fitsBelow
      ? trigger.bottom + GAP
      : Math.max(EDGE, trigger.top - GAP - menu.height),
    left: Math.min(
      Math.max(EDGE, trigger.right - menu.width),
      viewportWidth - menu.width - EDGE,
    ),
  }
}

/*
  A "⋯" button that opens a menu of row actions. The menu renders
  through a portal so the table's scroll area can't clip it, and is
  placed under the button (above it when there's no room below).

  Keyboard: Enter/Space/ArrowDown open it on the first item, ArrowUp
  on the last; arrows, Home and End move between items; Escape and
  Tab close it and return focus to the button. Clicking outside also
  closes it. While the page scrolls the menu follows the button,
  and closes once the button leaves the viewport.

  Disabled items stay focusable (aria-disabled) so keyboard and
  screen-reader users still find them and hear why they're disabled.
*/
function OverflowMenu({
  label,
  items,
  disabledReason,
  className = '',
}: OverflowMenuProps) {
  const [open, setOpen] = useState(false)
  const [position, setPosition] = useState<MenuPosition | null>(
    null,
  )

  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const initialFocus = useRef<'first' | 'last'>('first')
  const menuId = useId()

  const itemButtons = () =>
    Array.from(
      menuRef.current?.querySelectorAll<HTMLButtonElement>(
        '[role="menuitem"]',
      ) ?? [],
    )

  function openMenu(focus: 'first' | 'last') {
    initialFocus.current = focus
    setPosition(null)
    setOpen(true)
  }

  function closeMenu(returnFocus: boolean) {
    setOpen(false)

    if (returnFocus) {
      triggerRef.current?.focus()
    }
  }

  // Place the menu once it has rendered and can be measured.
  useLayoutEffect(() => {
    if (!open || !triggerRef.current || !menuRef.current) {
      return
    }

    setPosition(
      computePosition(triggerRef.current, menuRef.current) ?? {
        top: EDGE,
        left: EDGE,
      },
    )
  }, [open])

  useEffect(() => {
    if (!open || !position) {
      return
    }

    const buttons =
      menuRef.current?.querySelectorAll<HTMLButtonElement>(
        '[role="menuitem"]',
      ) ?? []

    const target =
      initialFocus.current === 'last'
        ? buttons[buttons.length - 1]
        : buttons[0]

    target?.focus()
  }, [open, position])

  useEffect(() => {
    if (!open) {
      return
    }

    function handlePointerDown(event: PointerEvent) {
      const target = event.target as Node

      if (
        menuRef.current?.contains(target) ||
        triggerRef.current?.contains(target)
      ) {
        return
      }

      setOpen(false)
    }

    // Follow the trigger while the page or table scrolls; close once it's gone.
    function handleScrollOrResize() {
      if (!triggerRef.current || !menuRef.current) {
        return
      }

      const next = computePosition(
        triggerRef.current,
        menuRef.current,
      )

      if (next) {
        setPosition(next)
      } else {
        setOpen(false)
      }
    }

    document.addEventListener('pointerdown', handlePointerDown)
    window.addEventListener('scroll', handleScrollOrResize, true)
    window.addEventListener('resize', handleScrollOrResize)

    return () => {
      document.removeEventListener('pointerdown', handlePointerDown)
      window.removeEventListener('scroll', handleScrollOrResize, true)
      window.removeEventListener('resize', handleScrollOrResize)
    }
  }, [open])

  function handleTriggerKeyDown(
    event: KeyboardEvent<HTMLButtonElement>,
  ) {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      openMenu('first')
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      openMenu('last')
    }
  }

  function handleMenuKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const buttons = itemButtons()
    const index = buttons.indexOf(
      document.activeElement as HTMLButtonElement,
    )

    const focusAt = (next: number) => {
      event.preventDefault()
      buttons[(next + buttons.length) % buttons.length]?.focus()
    }

    switch (event.key) {
      case 'ArrowDown':
        focusAt(index + 1)
        break
      case 'ArrowUp':
        focusAt(index - 1)
        break
      case 'Home':
        focusAt(0)
        break
      case 'End':
        focusAt(buttons.length - 1)
        break
      case 'Escape':
        event.preventDefault()
        event.stopPropagation()
        closeMenu(true)
        break
      case 'Tab':
        event.preventDefault()
        closeMenu(true)
        break
    }
  }

  function selectItem(item: OverflowMenuItem) {
    if (item.disabled) {
      return
    }

    /*
      Focus the button first, so a dialog opened by the item returns
      focus there when it closes.
    */
    closeMenu(true)
    item.onSelect()
  }

  const anyDisabled = items.some((item) => item.disabled)

  return (
    <>
      <button
        ref={triggerRef}
        className={`btn small overflow-trigger ${className}`.trim()}
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => (open ? closeMenu(false) : openMenu('first'))}
        onKeyDown={handleTriggerKeyDown}
      >
        <svg
          aria-hidden="true"
          width="16"
          height="4"
          viewBox="0 0 16 4"
          fill="currentColor"
        >
          <circle cx="2" cy="2" r="1.75" />
          <circle cx="8" cy="2" r="1.75" />
          <circle cx="14" cy="2" r="1.75" />
        </svg>
      </button>

      {open &&
        createPortal(
          <div
            ref={menuRef}
            id={menuId}
            className="overflow-menu"
            role="menu"
            aria-label={label}
            onKeyDown={handleMenuKeyDown}
            style={
              position
                ? { top: position.top, left: position.left }
                : { top: 0, left: 0, visibility: 'hidden' }
            }
          >
            {items.map((item) => (
              <button
                key={item.label}
                className={
                  item.destructive
                    ? 'overflow-item destructive'
                    : 'overflow-item'
                }
                type="button"
                role="menuitem"
                tabIndex={-1}
                aria-disabled={item.disabled || undefined}
                onClick={() => selectItem(item)}
              >
                {item.label}
              </button>
            ))}

            {anyDisabled && disabledReason && (
              <p className="overflow-note">{disabledReason}</p>
            )}
          </div>,
          document.body,
        )}
    </>
  )
}

export default OverflowMenu
