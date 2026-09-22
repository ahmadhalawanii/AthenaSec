import type { ConfirmModalContent } from '../types/confirmModalTypes'

export const LOGOUT_CONFIRMATION: ConfirmModalContent = {
  title: 'Sign out of AthenaSec?',
  message:
    'Are you sure you want to end your current AthenaSec session?',
  confirmLabel: 'Sign Out',
  cancelLabel: 'Cancel',
  tone: 'danger',
}
