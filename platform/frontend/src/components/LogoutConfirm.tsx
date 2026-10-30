import { LOGOUT_CONFIRMATION, LOGOUT_UNSAVED_NOTE } from '../data/confirmModalData'
import { useResponsePolicy } from '../hooks/useResponsePolicy'

import ConfirmModal from './ConfirmModal'

/*
  The sign-out confirmation. It adds one line when the Permissions draft has unsaved
  changes, since signing out ends the draft (it never carries over to the next person).
*/
function LogoutConfirm({ open, onCancel, onConfirm }: { open: boolean; onCancel: () => void; onConfirm: () => void }) {
  const { unsavedChanges } = useResponsePolicy()

  return (
    <ConfirmModal
      open={open}
      {...LOGOUT_CONFIRMATION}
      note={unsavedChanges > 0 ? LOGOUT_UNSAVED_NOTE : undefined}
      onCancel={onCancel}
      onConfirm={onConfirm}
    />
  )
}

export default LogoutConfirm
