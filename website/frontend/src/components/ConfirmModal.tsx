import { useEffect } from 'react'
import { createPortal } from 'react-dom'

import type { ConfirmModalProps } from '../types/confirmModalTypes'

function ConfirmModal({
  open,
  title,
  message,
  confirmLabel,
  cancelLabel,
  tone,
  onCancel,
  onConfirm,
}: ConfirmModalProps) {
  useEffect(() => {
    if (!open) {
      return
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        onCancel()
      }
    }

    window.addEventListener('keydown', handleKeyDown)

    return () => {
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [open, onCancel])

  if (!open) {
    return null
  }

  return createPortal(
    <div
      className="modal-backdrop"
      role="presentation"
      onClick={onCancel}
    >
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-modal-title"
        aria-describedby="confirm-modal-message"
        onClick={(event) => event.stopPropagation()}
      >
        <h2 id="confirm-modal-title">{title}</h2>

        <div className="modal-body">
          <p id="confirm-modal-message">{message}</p>
        </div>

        <div className="modal-actions">
          <button
            className="btn"
            type="button"
            onClick={onCancel}
            autoFocus
          >
            {cancelLabel}
          </button>

          <button
            className={`btn ${tone}`}
            type="button"
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

export default ConfirmModal
