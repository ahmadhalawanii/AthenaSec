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
  UserRole,
  UserStatus,
} from '../types/userManagementTypes'

import { initialUsers, emptyUserForm } from '../data/userManagementData'


function statusClass(status: UserStatus) {
  return status === 'Active' ? 'ok' : 'danger'
}

function roleClass(role: UserRole) {
  return role === 'Administrator' ? 'warn' : 'blue'
}

function UserManagementPage() {
  const [users, setUsers] =
    useState<UserRecord[]>(initialUsers)

  const [searchQuery, setSearchQuery] = useState('')
  const [roleFilter, setRoleFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')

  const [selectedUser, setSelectedUser] =
    useState<UserRecord | null>(null)

  const [modalMode, setModalMode] =
    useState<ModalMode>(null)

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

  const activeCount = users.filter(
    (user) => user.status === 'Active',
  ).length

  const suspendedCount = users.filter(
    (user) => user.status === 'Suspended',
  ).length

  const administratorCount = users.filter(
    (user) => user.role === 'Administrator',
  ).length

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

  function saveUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const validationError = validateUserForm()

    if (validationError) {
      setFormError(validationError)
      return
    }

    if (modalMode === 'add') {
      const highestUserNumber = users.reduce(
        (highestNumber, user) => {
          const userNumber = Number(
            user.id.replace('USR-', ''),
          )

          return Number.isNaN(userNumber)
            ? highestNumber
            : Math.max(highestNumber, userNumber)
        },
        0,
      )

      const newUser: UserRecord = {
        id: `USR-${String(
          highestUserNumber + 1,
        ).padStart(3, '0')}`,
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

      setUsers((currentUsers) => [
        ...currentUsers,
        newUser,
      ])

      setPageMessage(
        `${newUser.name} was added successfully.`,
      )

      closeModal()
      return
    }

    if (modalMode === 'edit' && selectedUser) {
      setUsers((currentUsers) =>
        currentUsers.map((user) =>
          user.id === selectedUser.id
            ? {
                ...user,
                name: userForm.name.trim(),
                email: userForm.email
                  .trim()
                  .toLowerCase(),
                role: userForm.role,
                status: userForm.status,
                department:
                  userForm.department.trim(),
                phone: userForm.phone.trim(),
                mfaEnabled: userForm.mfaEnabled,
              }
            : user,
        ),
      )

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

    setUsers((currentUsers) =>
      currentUsers.map((user) =>
        user.id === userId
          ? {
              ...user,
              status: nextStatus,
            }
          : user,
      ),
    )

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
      `${currentUser.name} was ${nextStatus.toLowerCase()}.`,
    )
  }

  function deleteSelectedUser() {
    if (!selectedUser) {
      return
    }

    setUsers((currentUsers) =>
      currentUsers.filter(
        (user) => user.id !== selectedUser.id,
      ),
    )

    setPageMessage(
      `${selectedUser.name} was deleted.`,
    )

    closeModal()
  }

  function resetSelectedUserPassword() {
    if (!selectedUser) {
      return
    }

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
            Manage AthenaSec analyst and administrator accounts,
            roles, access status, MFA, and temporary password resets.
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

      <div className="grid stats">
        <div className="stat">
          <strong>{users.length}</strong>
          <span>Total Users</span>
          <small>Current frontend accounts</small>
        </div>

        <div className="stat">
          <strong>{activeCount}</strong>
          <span>Active</span>
          <small>Can access AthenaSec</small>
        </div>

        <div className="stat">
          <strong>{suspendedCount}</strong>
          <span>Suspended</span>
          <small>Access temporarily disabled</small>
        </div>

        <div className="stat">
          <strong>{administratorCount}</strong>
          <span>Administrators</span>
          <small>Security-management access</small>
        </div>
      </div>

      {pageMessage && (
        <div
          className="notice"
          role="status"
          style={{ marginTop: '18px' }}
        >
          {pageMessage}
        </div>
      )}

      <div
        className="toolbar"
        style={{ marginTop: '18px' }}
      >
        <input
          className="field-input"
          type="search"
          placeholder="Search users"
          value={searchQuery}
          onChange={(event) =>
            setSearchQuery(event.target.value)
          }
        />

        <select
          className="select-input"
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
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>Actions</th>
                <th>Last Login</th>
              </tr>
            </thead>

            <tbody>
              {visibleUsers.map((user) => (
                <tr
                  key={user.id}
                  className="data-row"
                  data-search-record
                  data-page-target="user-management"
                >
                  <td>
                    <strong>{user.name}</strong>

                    <div
                      className="sub"
                      style={{
                        marginTop: '4px',
                        fontSize: '12px',
                      }}
                    >
                      {user.id} · {user.email}
                    </div>
                  </td>

                  <td>
                    <span
                      className={`pill ${roleClass(
                        user.role,
                      )}`}
                    >
                      {user.role}
                    </span>
                  </td>

                  <td>
                    <span
                      className={`pill ${statusClass(
                        user.status,
                      )}`}
                    >
                      {user.status}
                    </span>
                  </td>

                  <td className="actions-cell">
                    <button
                      className="btn small"
                      type="button"
                      onClick={() => openViewModal(user)}
                    >
                      View
                    </button>

                    <button
                      className="btn small"
                      type="button"
                      onClick={() => openEditModal(user)}
                    >
                      Edit
                    </button>

                    <button
                      className="btn small"
                      type="button"
                      onClick={() =>
                        openResetPasswordModal(user)
                      }
                    >
                      Reset Password
                    </button>

                    <button
                      className={
                        user.status === 'Active'
                          ? 'btn small danger'
                          : 'btn small primary'
                      }
                      type="button"
                      onClick={() =>
                        toggleUserStatus(user.id)
                      }
                    >
                      {user.status === 'Active'
                        ? 'Suspend'
                        : 'Activate'}
                    </button>

                    <button
                      className="btn small danger"
                      type="button"
                      onClick={() =>
                        openDeleteModal(user)
                      }
                    >
                      Delete
                    </button>
                  </td>

                  <td>{user.lastLogin}</td>
                </tr>
              ))}

              {visibleUsers.length === 0 && (
                <tr>
                  <td colSpan={5}>
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
        </div>
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
              className="modal"
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
                    ? 'Create a temporary frontend user account.'
                    : 'Update the selected frontend user account.'}
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
                      value={userForm.name}
                      onChange={handleFormChange}
                      placeholder="Example: Analyst D"
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
                      value={userForm.email}
                      onChange={handleFormChange}
                      placeholder="analyst.d@athenasec.com"
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
                      value={userForm.role}
                      onChange={handleFormChange}
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
                      value={userForm.status}
                      onChange={handleFormChange}
                    >
                      <option value="Active">
                        Active
                      </option>

                      <option value="Suspended">
                        Suspended
                      </option>
                    </select>
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
                      value={userForm.department}
                      onChange={handleFormChange}
                      placeholder="Security Operations"
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
                      value={userForm.phone}
                      onChange={handleFormChange}
                      placeholder="+971 50 555 0105"
                    />
                  </div>
                </div>

                <label
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    marginTop: '18px',
                  }}
                >
                  <input
                    name="mfaEnabled"
                    type="checkbox"
                    checked={userForm.mfaEnabled}
                    onChange={handleFormChange}
                  />

                  <span>Require MFA for this user</span>
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
                  className={`pill ${statusClass(
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
                  These account changes are temporary frontend
                  demonstrations and do not update real authentication
                  records.
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
                      : 'btn primary'
                  }
                  type="button"
                  onClick={() =>
                    toggleUserStatus(selectedUser.id)
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

      {modalMode === 'reset-password' &&
        selectedUser &&
        createPortal(
          <div
            className="modal-backdrop"
            role="presentation"
            onClick={closeModal}
          >
            <div
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
                  This only simulates the password-reset action.
                  No real credential will be changed.
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
                  This removes the account for the current
                  frontend session.
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
