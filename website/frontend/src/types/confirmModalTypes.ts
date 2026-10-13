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
  onCancel: () => void
  onConfirm: () => void
}
