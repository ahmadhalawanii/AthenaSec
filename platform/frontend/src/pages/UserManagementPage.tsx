import {
  useMemo,
  useState,
  type ChangeEvent,
  type FormEvent,
} from 'react'
import { createPortal } from 'react-dom'
import type {
  ModalMode,
  UserFormState,
  UserRecord,
  UserStatus,
} from '../types/userManagementTypes'
import type { IssuedCredentials, UserFields } from '../types/adminStateTypes'

import IdText from '../components/IdText'
import IssuedCredentialsModal from '../components/IssuedCredentialsModal'
import OverflowMenu from '../components/OverflowMenu'
import TableScroll from '../components/TableScroll'
import { accessReview, accountHealth } from '../data/statusSummary'
import { emptyUserForm } from '../data/userManagementData'
import { useAdminState } from '../hooks/useAdminState'
import { useDialog } from '../hooks/useDialog'
import { statusTone } from '../utils/statusTone'

const SELF_ACTION_REASON =
  'You cannot suspend, delete, or change the role of your own account.'

function UserManagementPage() {
  /*
    Shared admin state: changes reach search, the dashboard and the
    audit log. The signed-in account is resolved by ID once (by the
    provider), so the protection still holds if the administrator edits
    their own email address. The provider refuses self changes too.
  */
  const {
    users,
    currentUserId,
    saveUser: storeUser,
    toggleUserStatus: storeUserStatus,
    deleteUser,
    requireMfa,
    resetPassword,
    nextUserId,
    liveUsers,
  } = useAdminState()

  // Live mode: changes go to the backend; the issued sign-in details are shown once
  const isLive = liveUsers !== null
  const [issued, setIssued] = useState<IssuedCredentials | null>(null)
  const [busy, setBusy] = useState(false)

  function isCurrentUser(user: UserRecord) {
    return user.id === currentUserId
  }

  const [searchQuery, setSearchQuery] = useState('')
  const [roleFilter, setRoleFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')

  const [selectedUser, setSelectedUser] =
    useState<UserRecord | null>(null)

  const [modalMode, setModalMode] =
    useState<ModalMode>(null)

  const dialogRef = useDialog(closeModal)

  const editingOwnAccount =
    modalMode === 'edit' &&
    selectedUser !== null &&
    isCurrentUser(selectedUser)

  const [userForm, setUserForm] =
    useState<UserFormState>(emptyUserForm)

  const [formError, setFormError] = useState('')
  const [pageMessage, setPageMessage] = useState('')

  const visibleUsers = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return users.filter((user) => {
      const matchesSearch =
        normalizedQuery === '' ||
        user.id.toLowerCase().includes(normalizedQuery) ||
        user.name.toLowerCase().includes(normalizedQuery) ||
        user.email.toLowerCase().includes(normalizedQuery) ||
        user.role.toLowerCase().includes(normalizedQuery) ||
        user.department.toLowerCase().includes(normalizedQuery) ||
        user.phone.toLowerCase().includes(normalizedQuery)

      const matchesRole =
        roleFilter === 'all' || user.role === roleFilter

      const matchesStatus =
        statusFilter === 'all' ||
        user.status === statusFilter

      return matchesSearch && matchesRole && matchesStatus
    })
  }, [users, searchQuery, roleFilter, statusFilter])

  const health = accountHealth(users)
  const reviewUsers = accessReview(users)

  function resetFilters() {
    setSearchQuery('')
    setRoleFilter('all')
    setStatusFilter('all')
  }

  function closeModal() {
    setModalMode(null)
    setSelectedUser(null)
    setUserForm(emptyUserForm)
    setFormError('')
  }

  function openAddModal() {
    setSelectedUser(null)
    setUserForm(emptyUserForm)
    setFormError('')
    setModalMode('add')
  }

  function openViewModal(user: UserRecord) {
    setSelectedUser(user)
    setModalMode('view')
  }

  function openEditModal(user: UserRecord) {
    setSelectedUser(user)

    setUserForm({
      name: user.name,
      email: user.email,
      role: user.role,
      status: user.status,
      department: user.department,
      phone: user.phone,
      mfaEnabled: user.mfaEnabled,
    })

    setFormError('')
    setModalMode('edit')
  }

  function openDeleteModal(user: UserRecord) {
    setSelectedUser(user)
    setModalMode('delete')
  }

  function openResetPasswordModal(user: UserRecord) {
    setSelectedUser(user)
    setModalMode('reset-password')
  }

  function openResetMfaModal(user: UserRecord) {
    setSelectedUser(user)
    setModalMode('reset-mfa')
  }

  function resetSelectedUserMfa() {
    if (!selectedUser || !liveUsers) {
      return
    }

    const target = selectedUser

    void liveUsers.resetMfa(target.id).then((result) => {
      closeModal()

      if ('error' in result) {
        setPageMessage(`Not reset: ${result.error}`)
        return
      }

      setIssued(result.credentials)
      setPageMessage(`Two-factor was reset for ${target.name}.`)
    })
  }

  function handleFormChange(
    event:
      | ChangeEvent<HTMLInputElement>
      | ChangeEvent<HTMLSelectElement>,
  ) {
    const { name, value, type } = event.target

    const nextValue =
      type === 'checkbox'
        ? (event.target as HTMLInputElement).checked
        : value

    setUserForm((currentForm) => ({
      ...currentForm,
      [name]: nextValue,
    }))
  }

  function validateUserForm() {
    if (!userForm.name.trim()) {
      return 'User name is required.'
    }

    if (!userForm.email.trim()) {
      return 'Email address is required.'
    }

    const emailPattern =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/

    if (!emailPattern.test(userForm.email.trim())) {
      return 'Enter a valid email address.'
    }

    const duplicateUser = users.find(
      (user) =>
        user.email.toLowerCase() ===
          userForm.email.trim().toLowerCase() &&
        user.id !== selectedUser?.id,
    )

    if (duplicateUser) {
      return 'A user with this email already exists.'
    }

    if (!userForm.department.trim()) {
      return 'Department is required.'
    }

    if (!userForm.phone.trim()) {
      return 'Phone number is required.'
    }

    return ''
  }

  function formFields(): UserFields {
    return {
      name: userForm.name,
      email: userForm.email,
      role: userForm.role,
      department: userForm.department,
      phone: userForm.phone,
    }
  }

  // Live mode: the backend creates or edits the account; refusals stay in the form
  async function saveLiveUser() {
    if (!liveUsers || busy) {
      return
    }

    setBusy(true)

    if (modalMode === 'add') {
      const result = await liveUsers.create(formFields(), userForm.status === 'Active')
      setBusy(false)

      if ('error' in result) {
        setFormError(result.error)
        return
      }

      closeModal()
      setIssued(result.credentials)
      setPageMessage(`${result.credentials.user.name} was added. Share the sign-in details shown.`)
      return
    }

    if (modalMode === 'edit' && selectedUser) {
      const editingSelf = isCurrentUser(selectedUser)
      const error = await liveUsers.update(
        selectedUser.id,
        editingSelf ? { ...formFields(), role: selectedUser.role } : formFields(),
        editingSelf ? null : userForm.status === 'Active',
      )
      setBusy(false)

      if (error) {
        setFormError(error)
        return
      }

      setPageMessage(`${userForm.name.trim()} was updated successfully.`)
      closeModal()
    }
  }

  function saveUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const validationError = validateUserForm()

    if (validationError) {
      setFormError(validationError)
      return
    }

    if (isLive) {
      void saveLiveUser()
      return
    }

    if (modalMode === 'add') {
      const newUser: UserRecord = {
        id: nextUserId(),
        name: userForm.name.trim(),
        email: userForm.email.trim().toLowerCase(),
        role: userForm.role,
        status: userForm.status,
        department: userForm.department.trim(),
        phone: userForm.phone.trim(),
        mfaEnabled: userForm.mfaEnabled,
        lastLogin: 'Never',
        createdAt: 'Today',
      }

      storeUser(newUser)

      setPageMessage(
        `${newUser.name} was added successfully.`,
      )

      closeModal()
      return
    }

    if (modalMode === 'edit' && selectedUser) {
      const editingSelf = isCurrentUser(selectedUser)
      const user = users.find((item) => item.id === selectedUser.id) ?? selectedUser

      storeUser({
        ...user,
        name: userForm.name.trim(),
        email: userForm.email.trim().toLowerCase(),
        role: editingSelf ? user.role : userForm.role,
        status: editingSelf ? user.status : userForm.status,
        department: userForm.department.trim(),
        phone: userForm.phone.trim(),
        mfaEnabled: userForm.mfaEnabled,
      })

      setPageMessage(
        `${userForm.name.trim()} was updated successfully.`,
      )

      closeModal()
    }
  }

  function toggleUserStatus(userId: string) {
    const currentUser = users.find(
      (user) => user.id === userId,
    )

    if (!currentUser) {
      return
    }

    const nextStatus: UserStatus =
      currentUser.status === 'Active'
        ? 'Suspended'
        : 'Active'

    if (liveUsers) {
      if (isCurrentUser(currentUser)) {
        setPageMessage(SELF_ACTION_REASON)
        return
      }

      void liveUsers.setActive(userId, nextStatus === 'Active').then((error) => {
        if (error) {
          setPageMessage(`Not saved: ${error}`)
          return
        }

        setSelectedUser((selected) => (selected && selected.id === userId ? { ...selected, status: nextStatus } : selected))
        setPageMessage(`${currentUser.name} was ${nextStatus === 'Active' ? 'activated' : 'suspended'}.`)
      })
      return
    }

    // The controls for your own account are disabled; the shared state
    // refuses it as well, so a call that gets past the UI changes nothing
    if (!storeUserStatus(userId)) {
      setPageMessage(SELF_ACTION_REASON)
      return
    }

    setSelectedUser((currentSelectedUser) => {
      if (
        !currentSelectedUser ||
        currentSelectedUser.id !== userId
      ) {
        return currentSelectedUser
      }

      return {
        ...currentSelectedUser,
        status: nextStatus,
      }
    })

    setPageMessage(
      `${currentUser.name} was ${
        nextStatus === 'Active' ? 'activated' : 'suspended'
      }.`,
    )
  }

  function deleteSelectedUser() {
    if (!selectedUser) {
      return
    }

    if (liveUsers) {
      const target = selectedUser

      void liveUsers.remove(target.id).then((error) => {
        setPageMessage(error ? `Not deleted: ${error}` : `${target.name} was deleted.`)
        closeModal()
      })
      return
    }

    // Refused by the shared state for your own account (see toggleUserStatus)
    if (!deleteUser(selectedUser.id)) {
      setPageMessage(SELF_ACTION_REASON)
      closeModal()
      return
    }

    setPageMessage(
      `${selectedUser.name} was deleted.`,
    )

    closeModal()
  }

  function requireMfaFor(user: UserRecord) {
    if (!requireMfa(user.id)) {
      return
    }

    setPageMessage(`MFA is now required for ${user.name}.`)
  }

  function resetSelectedUserPassword() {
    if (!selectedUser) {
      return
    }

    if (liveUsers) {
      const target = selectedUser

      void liveUsers.resetPassword(target.id).then((result) => {
        closeModal()

        if ('error' in result) {
          setPageMessage(`Not reset: ${result.error}`)
          return
        }

        setIssued(result.credentials)
        setPageMessage(`A temporary password was issued for ${target.name}.`)
      })
      return
    }

    resetPassword(selectedUser.id)

    setPageMessage(
      `A temporary password was generated for ${selectedUser.name}.`,
    )

    closeModal()
  }

  return (
    <section
      className="page active"
      data-page="user-management"
      data-page-name="User Management"
      data-admin-only
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>User Management</h1>

          <p className="sub">
            Who can sign in, what they can do, and whether their account is protected.
          </p>
        </div>

        <button
          className="btn primary"
          type="button"
          onClick={openAddModal}
        >
          + Add User
        </button>
      </div>

      <section className="um-summary" aria-label="Access summary">
        <div className="card um-health" id="accountHealth">
          <div className="um-health-head">
            <h2>Account health</h2>
            <span className="sub">
              {health.total} {health.total === 1 ? 'account' : 'accounts'}
            </span>
          </div>

          <div
            className="um-health-bar"
            role="img"
            aria-label={`${health.activeWithMfa} active with MFA, ${health.activeWithoutMfa} active without MFA, ${health.suspended} suspended`}
          >
            <span className="ok" style={{ flexGrow: health.activeWithMfa }} />
            <span className="warn" style={{ flexGrow: health.activeWithoutMfa }} />
            <span className="danger" style={{ flexGrow: health.suspended }} />
          </div>

          <dl className="um-health-counts">
            <div data-count="active-with-mfa">
              <dd>{health.activeWithMfa}</dd>
              <dt>active with MFA</dt>
            </div>
            <div data-count="suspended" className={health.suspended > 0 ? 'attention' : undefined}>
              <dd>{health.suspended}</dd>
              <dt>suspended</dt>
            </div>
            <div data-count="administrators">
              <dd>{health.administrators}</dd>
              <dt>{health.administrators === 1 ? 'administrator' : 'administrators'}</dt>
            </div>
            <div data-count="analysts">
              <dd>{health.analysts}</dd>
              <dt>{health.analysts === 1 ? 'analyst' : 'analysts'}</dt>
            </div>
          </dl>
        </div>

        <div className="card key um-review" id="accessReview">
          <h2>Access review</h2>

          {reviewUsers.length === 0 ? (
            <p className="um-review-text" data-review="clear">
              No account needs review. Every suspended account has MFA turned on.
            </p>
          ) : (
            <ul className="um-review-list">
              {reviewUsers.map((user) => (
                <li key={user.id} data-review-id={user.id}>
                  <p className="um-review-text">
                    {user.name} is suspended and has MFA turned off (last sign-in{' '}
                    {user.lastLogin}). Remove the account or require MFA before
                    reactivating it.
                  </p>

                  <div className="um-review-actions">
                    <button
                      className="btn"
                      type="button"
                      onClick={() => requireMfaFor(user)}
                    >
                      Require MFA
                    </button>

                    <button
                      className="btn danger"
                      type="button"
                      onClick={() => openDeleteModal(user)}
                      disabled={isCurrentUser(user)}
                      title={
                        isCurrentUser(user)
                          ? SELF_ACTION_REASON
                          : undefined
                      }
                    >
                      Remove account
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      {pageMessage && (
        <div
          className="notice"
          role="status"
        >
          {pageMessage}
        </div>
      )}

      <div
        className="toolbar"
      >
        <input
          className="field-input"
          type="search"
          name="userSearch"
          autoComplete="off"
          aria-label="Search users"
          placeholder="Search users…"
          value={searchQuery}
          onChange={(event) =>
            setSearchQuery(event.target.value)
          }
        />

        <select
          className="select-input"
          name="roleFilter"
          autoComplete="off"
          aria-label="Filter by role"
          value={roleFilter}
          onChange={(event) =>
            setRoleFilter(event.target.value)
          }
        >
          <option value="all">All Roles</option>
          <option value="Analyst">Analyst</option>
          <option value="Administrator">
            Administrator
          </option>
        </select>

        <select
          className="select-input"
          name="statusFilter"
          autoComplete="off"
          aria-label="Filter by status"
          value={statusFilter}
          onChange={(event) =>
            setStatusFilter(event.target.value)
          }
        >
          <option value="all">All Statuses</option>
          <option value="Active">Active</option>
          <option value="Suspended">Suspended</option>
        </select>

        <button
          className="btn"
          type="button"
          onClick={resetFilters}
        >
          Reset Filters
        </button>

        <span className="pill blue">
          {visibleUsers.length} visible
        </span>
      </div>

      <div className="card">
        <TableScroll label="Users">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>MFA</th>
                <th>Department</th>
                <th className="actions-col">Actions</th>
                <th>Last sign-in</th>
              </tr>
            </thead>

            <tbody>
              {visibleUsers.map((user) => (
                <tr
                  key={user.id}
                  className="data-row"
                  data-search-record
                  data-page-target="user-management"
                  data-record-id={user.id}
                >
                  <td>
                    <div className="um-user">
                      <span className="um-user-text">
                        <strong>
                          {user.name}
                          {isCurrentUser(user) && (
                            <span className="um-you"> (you)</span>
                          )}
                        </strong>

                        <span className="sub um-user-sub">
                          <IdText>{`${user.id} · `}</IdText>
                          {/* A narrow column breaks the address after the "@", never mid-word */}
                          {user.email.slice(0, user.email.indexOf('@') + 1)}
                          <wbr />
                          {user.email.slice(user.email.indexOf('@') + 1)}
                        </span>
                      </span>
                    </div>
                  </td>

                  <td>
                    <span
                      className={`pill ${statusTone(
                        user.role,
                      )}`}
                    >
                      {user.role}
                    </span>
                  </td>

                  <td>
                    <span className="um-status" data-field="status">
                      <span
                        className={`audit-dot ${statusTone(user.status)}`}
                        aria-hidden="true"
                      />
                      {user.status}
                    </span>
                  </td>

                  <td>
                    <span
                      className={user.mfaEnabled ? 'um-mfa' : 'um-mfa off'}
                      data-field="mfa"
                    >
                      {user.mfaEnabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>

                  <td data-field="department">{user.department}</td>

                  {/*
                    Wide screens show every action. On phones the
                    four after View move into the "⋯" menu (see
                    user-management-table-fix.css).
                  */}
                  <td className="actions-cell">
                    <button
                      className="btn small"
                      type="button"
                      aria-label={`View ${user.name}`}
                      onClick={() => openViewModal(user)}
                    >
                      View
                    </button>

                    <button
                      className="btn small row-action-inline"
                      type="button"
                      aria-label={`Edit user ${user.name}`}
                      onClick={() => openEditModal(user)}
                    >
                      Edit
                    </button>

                    <button
                      className="btn small row-action-inline"
                      type="button"
                      aria-label={`Reset Password for ${user.name}`}
                      onClick={() =>
                        openResetPasswordModal(user)
                      }
                    >
                      Reset Password
                    </button>

                    {isLive && (
                      <button
                        className="btn small row-action-inline"
                        type="button"
                        aria-label={`Reset two-factor for ${user.name}`}
                        onClick={() => openResetMfaModal(user)}
                      >
                        Reset 2FA
                      </button>
                    )}

                    <button
                      className={
                        user.status === 'Active'
                          ? 'btn small danger row-action-inline'
                          : 'btn small row-action-inline'
                      }
                      type="button"
                      aria-label={`${user.status === 'Active' ? 'Suspend' : 'Activate'} user ${user.name}`}
                      onClick={() =>
                        toggleUserStatus(user.id)
                      }
                      disabled={isCurrentUser(user)}
                      title={
                        isCurrentUser(user)
                          ? SELF_ACTION_REASON
                          : undefined
                      }
                    >
                      {user.status === 'Active'
                        ? 'Suspend'
                        : 'Activate'}
                    </button>

                    <button
                      className="btn small danger row-action-inline"
                      type="button"
                      aria-label={`Delete user ${user.name}`}
                      onClick={() =>
                        openDeleteModal(user)
                      }
                      disabled={isCurrentUser(user)}
                      title={
                        isCurrentUser(user)
                          ? SELF_ACTION_REASON
                          : undefined
                      }
                    >
                      Delete
                    </button>

                    <OverflowMenu
                      className="row-action-overflow"
                      label={`More actions for ${user.name}`}
                      disabledReason={SELF_ACTION_REASON}
                      items={[
                        {
                          label: 'Edit',
                          onSelect: () => openEditModal(user),
                        },
                        {
                          label: 'Reset Password',
                          onSelect: () =>
                            openResetPasswordModal(user),
                        },
                        ...(isLive
                          ? [{ label: 'Reset Two-Factor', onSelect: () => openResetMfaModal(user) }]
                          : []),
                        {
                          label:
                            user.status === 'Active'
                              ? 'Suspend'
                              : 'Activate',
                          onSelect: () =>
                            toggleUserStatus(user.id),
                          disabled: isCurrentUser(user),
                          destructive: user.status === 'Active',
                        },
                        {
                          label: 'Delete',
                          onSelect: () => openDeleteModal(user),
                          disabled: isCurrentUser(user),
                          destructive: true,
                        },
                      ]}
                    />

                    {isCurrentUser(user) && (
                      <span className="um-self-note row-action-inline">
                        You can't suspend or delete your own account.
                      </span>
                    )}
                  </td>

                  <td>{user.lastLogin}</td>
                </tr>
              ))}

              {visibleUsers.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <div className="empty">
                      <strong>No users found</strong>

                      <p className="sub">
                        No users match the current search and
                        filters.
                      </p>

                      <button
                        className="btn primary"
                        type="button"
                        onClick={resetFilters}
                        style={{ marginTop: '14px' }}
                      >
                        Clear Filters
                      </button>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </TableScroll>
      </div>

      {(modalMode === 'add' ||
        modalMode === 'edit') &&
        createPortal(
          <div
            className="modal-backdrop"
            role="presentation"
            onClick={closeModal}
          >
            <form
              ref={dialogRef}
              className="modal"
              role="dialog"
              aria-modal="true"
              aria-label={
                modalMode === 'add' ? 'Add user' : 'Edit user'
              }
              onSubmit={saveUser}
              onClick={(event) =>
                event.stopPropagation()
              }
              style={{
                maxHeight: '90vh',
                overflowY: 'auto',
              }}
            >
              <h2>
                {modalMode === 'add'
                  ? 'Add User'
                  : `Edit ${selectedUser?.id}`}
              </h2>

              <div className="modal-body">
                <p className="sub">
                  {modalMode === 'add'
                    ? 'Create a user account.'
                    : 'Update this user account.'}
                </p>

                {formError && (
                  <div
                    className="notice"
                    style={{ marginTop: '14px' }}
                  >
                    {formError}
                  </div>
                )}

                <div
                  className="grid two"
                  style={{ marginTop: '18px' }}
                >
                  <div>
                    <label
                      className="form-label"
                      htmlFor="userName"
                    >
                      Full Name
                    </label>

                    <input
                      className="field-input"
                      id="userName"
                      name="name"
                      autoComplete="off"
                      value={userForm.name}
                      onChange={handleFormChange}
                      placeholder="Example: Analyst D…"
                    />
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="userEmail"
                    >
                      Email Address
                    </label>

                    <input
                      className="field-input"
                      id="userEmail"
                      name="email"
                      type="email"
                      autoComplete="off"
                      spellCheck={false}
                      value={userForm.email}
                      onChange={handleFormChange}
                      placeholder="analyst.d@athenasec.com…"
                    />
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="userRole"
                    >
                      Role
                    </label>

                    <select
                      className="select-input"
                      id="userRole"
                      name="role"
                      autoComplete="off"
                      value={userForm.role}
                      onChange={handleFormChange}
                      disabled={editingOwnAccount}
                      aria-describedby={
                        editingOwnAccount
                          ? 'selfEditNote'
                          : undefined
                      }
                    >
                      <option value="Analyst">
                        Analyst
                      </option>

                      <option value="Administrator">
                        Administrator
                      </option>
                    </select>
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="userStatus"
                    >
                      Status
                    </label>

                    <select
                      className="select-input"
                      id="userStatus"
                      name="status"
                      autoComplete="off"
                      value={userForm.status}
                      onChange={handleFormChange}
                      disabled={editingOwnAccount}
                      aria-describedby={
                        editingOwnAccount
                          ? 'selfEditNote'
                          : undefined
                      }
                    >
                      <option value="Active">
                        Active
                      </option>

                      <option value="Suspended">
                        Suspended
                      </option>
                    </select>

                    {editingOwnAccount && (
                      <p className="sub" id="selfEditNote">
                        {SELF_ACTION_REASON}
                      </p>
                    )}
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="userDepartment"
                    >
                      Department
                    </label>

                    <input
                      className="field-input"
                      id="userDepartment"
                      name="department"
                      autoComplete="off"
                      value={userForm.department}
                      onChange={handleFormChange}
                      placeholder="Security Operations…"
                    />
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="userPhone"
                    >
                      Phone
                    </label>

                    <input
                      className="field-input"
                      id="userPhone"
                      name="phone"
                      type="tel"
                      autoComplete="off"
                      value={userForm.phone}
                      onChange={handleFormChange}
                      placeholder="+971 50 555 0105…"
                    />
                  </div>
                </div>

                <label className="check-row" style={{ marginTop: '18px' }}>
                  <input
                    name="mfaEnabled"
                    type="checkbox"
                    checked={isLive || userForm.mfaEnabled}
                    onChange={handleFormChange}
                    disabled={isLive}
                  />

                  <span>
                    {isLive ? 'Two-factor sign-in is required for every account' : 'Require MFA for this user'}
                  </span>
                </label>
              </div>

              <div className="modal-actions">
                <button
                  className="btn"
                  type="button"
                  onClick={closeModal}
                >
                  Cancel
                </button>

                <button
                  className="btn primary"
                  type="submit"
                >
                  {modalMode === 'add'
                    ? 'Add User'
                    : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>,
          document.body,
        )}

      {modalMode === 'view' &&
        selectedUser &&
        createPortal(
          <div
            className="modal-backdrop"
            role="presentation"
            onClick={closeModal}
          >
            <div
              ref={dialogRef}
              className="modal"
              role="dialog"
              aria-modal="true"
              aria-label="User details"
              onClick={(event) =>
                event.stopPropagation()
              }
              style={{
                maxHeight: '90vh',
                overflowY: 'auto',
              }}
            >
              <div className="headline">
                <div>
                  <span className="sub">
                    User Details
                  </span>

                  <h2>{selectedUser.name}</h2>
                </div>

                <span
                  className={`pill ${statusTone(
                    selectedUser.status,
                  )}`}
                >
                  {selectedUser.status}
                </span>
              </div>

              <div className="modal-body">
                <div className="kv">
                  <span>User ID</span>
                  <strong>{selectedUser.id}</strong>
                </div>

                <div className="kv">
                  <span>Email</span>
                  <strong>{selectedUser.email}</strong>
                </div>

                <div className="kv">
                  <span>Role</span>
                  <strong>{selectedUser.role}</strong>
                </div>

                <div className="kv">
                  <span>Department</span>
                  <strong>
                    {selectedUser.department}
                  </strong>
                </div>

                <div className="kv">
                  <span>Phone</span>
                  <strong>{selectedUser.phone}</strong>
                </div>

                <div className="kv">
                  <span>MFA</span>
                  <strong>
                    {selectedUser.mfaEnabled
                      ? 'Enabled'
                      : 'Disabled'}
                  </strong>
                </div>

                <div className="kv">
                  <span>Last Login</span>
                  <strong>
                    {selectedUser.lastLogin}
                  </strong>
                </div>

                <div className="kv">
                  <span>Created</span>
                  <strong>
                    {selectedUser.createdAt}
                  </strong>
                </div>

                <div
                  className="notice"
                  style={{ marginTop: '16px' }}
                >
                  Account changes are simulated in this demo and
                  don’t affect real sign-in records.
                </div>
              </div>

              <div className="modal-actions">
                <button
                  className="btn"
                  type="button"
                  onClick={closeModal}
                >
                  Close
                </button>

                <button
                  className="btn"
                  type="button"
                  onClick={() =>
                    openResetPasswordModal(selectedUser)
                  }
                >
                  Reset Password
                </button>

                <button
                  className="btn primary"
                  type="button"
                  onClick={() =>
                    openEditModal(selectedUser)
                  }
                >
                  Edit User
                </button>

                <button
                  className={
                    selectedUser.status === 'Active'
                      ? 'btn danger'
                      : 'btn'
                  }
                  type="button"
                  onClick={() =>
                    toggleUserStatus(selectedUser.id)
                  }
                  disabled={isCurrentUser(selectedUser)}
                  title={
                    isCurrentUser(selectedUser)
                      ? SELF_ACTION_REASON
                      : undefined
                  }
                >
                  {selectedUser.status === 'Active'
                    ? 'Suspend User'
                    : 'Activate User'}
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}

      {issued && <IssuedCredentialsModal issued={issued} onClose={() => setIssued(null)} />}

      {modalMode === 'reset-mfa' &&
        selectedUser &&
        createPortal(
          <div className="modal-backdrop" role="presentation" onClick={closeModal}>
            <div
              ref={dialogRef}
              className="modal"
              role="dialog"
              aria-modal="true"
              aria-label="Reset two-factor"
              onClick={(event) => event.stopPropagation()}
            >
              <h2>Reset Two-Factor</h2>

              <div className="modal-body">
                <p>
                  Give <strong>{selectedUser.name}</strong> a new authenticator setup?
                </p>
                <p className="sub" style={{ marginTop: '10px' }}>
                  Use this when they lost their phone or authenticator app. Their old codes stop
                  working at once and they are signed out everywhere. Their password stays the same.
                </p>
              </div>

              <div className="modal-actions">
                <button className="btn" type="button" onClick={closeModal}>
                  Cancel
                </button>
                <button className="btn primary" type="button" onClick={resetSelectedUserMfa}>
                  Reset Two-Factor
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}

      {modalMode === 'reset-password' &&
        selectedUser &&
        createPortal(
          <div
            className="modal-backdrop"
            role="presentation"
            onClick={closeModal}
          >
            <div
              ref={dialogRef}
              className="modal"
              role="dialog"
              aria-modal="true"
              aria-label="Reset user password"
              onClick={(event) =>
                event.stopPropagation()
              }
            >
              <h2>Reset Password</h2>

              <div className="modal-body">
                <p>
                  Generate a temporary password for{' '}
                  <strong>{selectedUser.name}</strong>?
                </p>

                <p
                  className="sub"
                  style={{ marginTop: '10px' }}
                >
                  {isLive
                    ? 'Their current password stops working at once and they are signed out everywhere. Two-factor stays as it is.'
                    : 'This only simulates the password-reset action. No real credential will be changed.'}
                </p>
              </div>

              <div className="modal-actions">
                <button
                  className="btn"
                  type="button"
                  onClick={closeModal}
                >
                  Cancel
                </button>

                <button
                  className="btn primary"
                  type="button"
                  onClick={resetSelectedUserPassword}
                >
                  Generate Temporary Password
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}

      {modalMode === 'delete' &&
        selectedUser &&
        createPortal(
          <div
            className="modal-backdrop"
            role="presentation"
            onClick={closeModal}
          >
            <div
              ref={dialogRef}
              className="modal"
              role="dialog"
              aria-modal="true"
              aria-label="Delete user"
              onClick={(event) =>
                event.stopPropagation()
              }
            >
              <h2>Delete User</h2>

              <div className="modal-body">
                <p>
                  Delete{' '}
                  <strong>{selectedUser.name}</strong>?
                </p>

                <p
                  className="sub"
                  style={{ marginTop: '10px' }}
                >
                  In this demo the account comes back when you
                  sign out or reload.
                </p>
              </div>

              <div className="modal-actions">
                <button
                  className="btn"
                  type="button"
                  onClick={closeModal}
                >
                  Cancel
                </button>

                <button
                  className="btn danger"
                  type="button"
                  onClick={deleteSelectedUser}
                >
                  Delete User
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}
    </section>
  )
}

export default UserManagementPage
