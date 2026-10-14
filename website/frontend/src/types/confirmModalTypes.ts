export type ConfirmModalTone = 'primary' | 'danger'

export type ConfirmModalContent = {
  title: string
  message: string
  confirmLabel: string
  cancelLabel: string
  tone: ConfirmModalTone
}

export type ConfirmModalProps = ConfirmModalContent & {
  open: boolean
  // An extra line under the message (for example what would be lost)
  note?: string
  onCancel: () => void
  onConfirm: () => void
}
