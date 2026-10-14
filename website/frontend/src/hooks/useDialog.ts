import { useCallback, useEffect, useRef } from 'react'

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ')

function focusableElements(container: HTMLElement) {
  return Array.from(
    container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
  ).filter((element) => element.getClientRects().length > 0)
}

/*
  Shared modal behaviour for every dialog and drawer:
  - Escape calls onClose
  - Tab and Shift+Tab stay inside the dialog
  - focus moves to the dialog's first focusable element when it
    opens and returns to the trigger when it closes

  Don't use autoFocus inside a dialog: React applies it before this
  ref runs, so the trigger is never recorded and focus can't return.
  Order the elements so the one to focus first comes first.

  Attach the returned ref to the element with role="dialog".
  The dialog is treated as open while that element is mounted.
*/
export function useDialog(onClose: () => void) {
  const onCloseRef = useRef(onClose)

  useEffect(() => {
    onCloseRef.current = onClose
  }, [onClose])

  return useCallback((dialog: HTMLElement | null) => {
    if (!dialog) {
      return
    }

    const previouslyFocused =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null

    if (!dialog.hasAttribute('tabindex')) {
      dialog.setAttribute('tabindex', '-1')
    }

    if (!dialog.contains(document.activeElement)) {
      const [firstElement] = focusableElements(dialog)
      ;(firstElement ?? dialog).focus()
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (!dialog) {
        return
      }

      if (event.key === 'Escape') {
        event.preventDefault()
        onCloseRef.current()
        return
      }

      if (event.key !== 'Tab') {
        return
      }

      const elements = focusableElements(dialog)

      if (elements.length === 0) {
        event.preventDefault()
        dialog.focus()
        return
      }

      const firstElement = elements[0]
      const lastElement = elements[elements.length - 1]
      const active = document.activeElement

      if (!dialog.contains(active)) {
        event.preventDefault()
        firstElement.focus()
      } else if (
        event.shiftKey &&
        (active === firstElement || active === dialog)
      ) {
        event.preventDefault()
        lastElement.focus()
      } else if (!event.shiftKey && active === lastElement) {
        event.preventDefault()
        firstElement.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)

    return () => {
      document.removeEventListener('keydown', handleKeyDown)

      if (previouslyFocused?.isConnected) {
        previouslyFocused.focus()
      }
    }
  }, [])
}
