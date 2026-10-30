import type { ConfirmModalContent } from '../types/confirmModalTypes'

export const LOGOUT_CONFIRMATION: ConfirmModalContent = {
  title: 'Sign out of AthenaSec?',
  message:
    'Are you sure you want to end your current AthenaSec session?',
  confirmLabel: 'Sign Out',
  cancelLabel: 'Cancel',
  tone: 'danger',
}

// Added under the message while the Permissions draft has unsaved changes
export const LOGOUT_UNSAVED_NOTE =
  'You have unsaved changes to the response policy. They will be lost.'
