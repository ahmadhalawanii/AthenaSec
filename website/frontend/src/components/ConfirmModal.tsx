import { createPortal } from 'react-dom'

import { useDialog } from '../hooks/useDialog'
import type { ConfirmModalProps } from '../types/confirmModalTypes'

function ConfirmModal({
  open,
  title,
  message,
  note,
  confirmLabel,
  cancelLabel,
  tone,
  onCancel,
  onConfirm,
}: ConfirmModalProps) {
  const dialogRef = useDialog(onCancel)

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
        ref={dialogRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-modal-title"
        aria-describedby={note ? 'confirm-modal-message confirm-modal-note' : 'confirm-modal-message'}
        onClick={(event) => event.stopPropagation()}
      >
        <h2 id="confirm-modal-title">{title}</h2>

        <div className="modal-body">
          <p id="confirm-modal-message">{message}</p>

          {note && <p id="confirm-modal-note" data-field="confirmNote">{note}</p>}
        </div>

        <div className="modal-actions">
          {/* First focusable, so useDialog focuses it on open */}
          <button
            className="btn"
            type="button"
            onClick={onCancel}
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