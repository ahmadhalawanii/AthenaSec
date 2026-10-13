import {
  useMemo,
  useState,
  type ChangeEvent,
  type FormEvent,
} from 'react'
import { createPortal } from 'react-dom'
import type {
  ApprovalMode,
  ModalMode,
  PolicyAction,
  PolicyFormState,
  PolicyStatus,
  ResponsePolicy,
} from '../types/responsePoliciesTypes'

import { initialPolicies, emptyPolicyForm, allowedActions } from '../data/responsePoliciesData'



function statusClass(status: PolicyStatus) {
  return status === 'Enabled' ? 'ok' : 'muted'
}

function approvalClass(approvalMode: ApprovalMode) {
  if (approvalMode === 'Automatic') {
    return 'blue'
  }

  if (approvalMode === 'Administrator Approval') {
    return 'danger'
  }

  return 'warn'
}

function ResponsePoliciesPage() {
  const [policies, setPolicies] =
    useState<ResponsePolicy[]>(initialPolicies)

  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [approvalFilter, setApprovalFilter] = useState('all')

  const [selectedPolicy, setSelectedPolicy] =
    useState<ResponsePolicy | null>(null)

  const [modalMode, setModalMode] =
    useState<ModalMode>(null)

  const [policyForm, setPolicyForm] =
    useState<PolicyFormState>(emptyPolicyForm)

  const [formError, setFormError] = useState('')
  const [pageMessage, setPageMessage] = useState('')

  const visiblePolicies = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return policies.filter((policy) => {
      const actionText = policy.actions.join(' ').toLowerCase()

      const matchesSearch =
        normalizedQuery === '' ||
        policy.id.toLowerCase().includes(normalizedQuery) ||
        policy.name.toLowerCase().includes(normalizedQuery) ||
        policy.condition.toLowerCase().includes(normalizedQuery) ||
        policy.approvalMode
          .toLowerCase()
          .includes(normalizedQuery) ||
        policy.description
          .toLowerCase()
          .includes(normalizedQuery) ||
        actionText.includes(normalizedQuery)

      const matchesStatus =
        statusFilter === 'all' ||
        policy.status === statusFilter

      const matchesApproval =
        approvalFilter === 'all' ||
        policy.approvalMode === approvalFilter

      return (
        matchesSearch &&
        matchesStatus &&
        matchesApproval
      )
    })
  }, [
    policies,
    searchQuery,
    statusFilter,
    approvalFilter,
  ])

  const enabledCount = policies.filter(
    (policy) => policy.status === 'Enabled',
  ).length

  const automaticCount = policies.filter(
    (policy) =>
      policy.approvalMode === 'Automatic' &&
      policy.status === 'Enabled',
  ).length

  const approvalRequiredCount = policies.filter(
    (policy) =>
      policy.approvalMode !== 'Automatic' &&
      policy.status === 'Enabled',
  ).length

  function resetFilters() {
    setSearchQuery('')
    setStatusFilter('all')
    setApprovalFilter('all')
  }

  function closeModal() {
    setModalMode(null)
    setSelectedPolicy(null)
    setPolicyForm(emptyPolicyForm)
    setFormError('')
  }

  function openAddModal() {
    setSelectedPolicy(null)
    setPolicyForm(emptyPolicyForm)
    setFormError('')
    setModalMode('add')
  }

  function openViewModal(policy: ResponsePolicy) {
    setSelectedPolicy(policy)
    setModalMode('view')
  }

  function openEditModal(policy: ResponsePolicy) {
    setSelectedPolicy(policy)

    setPolicyForm({
      name: policy.name,
      condition: policy.condition,
      actions: policy.actions.join(', '),
      approvalMode: policy.approvalMode,
      status: policy.status,
      riskThreshold: String(policy.riskThreshold),
      description: policy.description,
    })

    setFormError('')
    setModalMode('edit')
  }

  function openDeleteModal(policy: ResponsePolicy) {
    setSelectedPolicy(policy)
    setModalMode('delete')
  }

  function handleFormChange(
    event:
      | ChangeEvent<HTMLInputElement>
      | ChangeEvent<HTMLSelectElement>
      | ChangeEvent<HTMLTextAreaElement>,
  ) {
    const { name, value } = event.target

    setPolicyForm((currentForm) => ({
      ...currentForm,
      [name]: value,
    }))
  }

  function parseActions(actionsText: string) {
    const requestedActions = actionsText
      .split(',')
      .map((action) => action.trim())
      .filter(Boolean)

    const validActions = requestedActions.filter(
      (action): action is PolicyAction =>
        allowedActions.includes(action as PolicyAction),
    )

    return validActions
  }

  function validatePolicyForm() {
    if (!policyForm.name.trim()) {
      return 'Policy name is required.'
    }

    if (!policyForm.condition.trim()) {
      return 'Policy condition is required.'
    }

    const parsedActions = parseActions(policyForm.actions)

    if (parsedActions.length === 0) {
      return `Enter at least one valid action: ${allowedActions.join(
        ', ',
      )}.`
    }

    const riskThreshold = Number(
      policyForm.riskThreshold,
    )

    if (
      Number.isNaN(riskThreshold) ||
      riskThreshold < 0 ||
      riskThreshold > 100
    ) {
      return 'Risk threshold must be between 0 and 100.'
    }

    if (!policyForm.description.trim()) {
      return 'Policy description is required.'
    }

    return ''
  }

  function savePolicy(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    const validationError = validatePolicyForm()

    if (validationError) {
      setFormError(validationError)
      return
    }

    const parsedActions = parseActions(
      policyForm.actions,
    )

    const riskThreshold = Number(
      policyForm.riskThreshold,
    )

    if (modalMode === 'add') {
      const highestPolicyNumber = policies.reduce(
        (highestNumber, policy) => {
          const policyNumber = Number(
            policy.id.replace('POL-', ''),
          )

          return Number.isNaN(policyNumber)
            ? highestNumber
            : Math.max(highestNumber, policyNumber)
        },
        0,
      )

      const newPolicy: ResponsePolicy = {
        id: `POL-${String(
          highestPolicyNumber + 1,
        ).padStart(3, '0')}`,
        name: policyForm.name.trim(),
        condition: policyForm.condition.trim(),
        actions: parsedActions,
        approvalMode: policyForm.approvalMode,
        status: policyForm.status,
        riskThreshold,
        description: policyForm.description.trim(),
        lastUpdated: 'Just now',
      }

      setPolicies((currentPolicies) => [
        ...currentPolicies,
        newPolicy,
      ])

      setPageMessage(
        `${newPolicy.name} was added successfully.`,
      )

      closeModal()
      return
    }

    if (modalMode === 'edit' && selectedPolicy) {
      setPolicies((currentPolicies) =>
        currentPolicies.map((policy) =>
          policy.id === selectedPolicy.id
            ? {
                ...policy,
                name: policyForm.name.trim(),
                condition:
                  policyForm.condition.trim(),
                actions: parsedActions,
                approvalMode:
                  policyForm.approvalMode,
                status: policyForm.status,
                riskThreshold,
                description:
                  policyForm.description.trim(),
                lastUpdated: 'Just now',
              }
            : policy,
        ),
      )

      setPageMessage(
        `${policyForm.name.trim()} was updated successfully.`,
      )

      closeModal()
    }
  }

  function togglePolicyStatus(policyId: string) {
    const currentPolicy = policies.find(
      (policy) => policy.id === policyId,
    )

    if (!currentPolicy) {
      return
    }

    const nextStatus: PolicyStatus =
      currentPolicy.status === 'Enabled'
        ? 'Disabled'
        : 'Enabled'

    setPolicies((currentPolicies) =>
      currentPolicies.map((policy) =>
        policy.id === policyId
          ? {
              ...policy,
              status: nextStatus,
              lastUpdated: 'Just now',
            }
          : policy,
      ),
    )

    setSelectedPolicy((currentSelectedPolicy) => {
      if (
        !currentSelectedPolicy ||
        currentSelectedPolicy.id !== policyId
      ) {
        return currentSelectedPolicy
      }

      return {
        ...currentSelectedPolicy,
        status: nextStatus,
        lastUpdated: 'Just now',
      }
    })

    setPageMessage(
      `${currentPolicy.name} was ${nextStatus.toLowerCase()}.`,
    )
  }

  function deleteSelectedPolicy() {
    if (!selectedPolicy) {
      return
    }

    setPolicies((currentPolicies) =>
      currentPolicies.filter(
        (policy) => policy.id !== selectedPolicy.id,
      ),
    )

    setPageMessage(
      `${selectedPolicy.name} was deleted.`,
    )

    closeModal()
  }

  return (
    <section
      className="page active"
      data-page="response-policies"
      data-page-name="Response Policies"
      data-admin-only
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Response Policies</h1>

          <p className="sub">
            Manage the conditions, approval modes, and actions
            permitted for automated incident response.
          </p>
        </div>

        <button
          className="btn primary"
          type="button"
          onClick={openAddModal}
        >
          + Add Policy
        </button>
      </div>

      <div className="grid stats">
        <div className="stat">
          <strong>{policies.length}</strong>
          <span>Total Policies</span>
          <small>Current frontend policies</small>
        </div>

        <div className="stat">
          <strong>{enabledCount}</strong>
          <span>Enabled</span>
          <small>Available for response matching</small>
        </div>

        <div className="stat">
          <strong>{automaticCount}</strong>
          <span>Automatic</span>
          <small>Enabled AI-managed policies</small>
        </div>

        <div className="stat">
          <strong>{approvalRequiredCount}</strong>
          <span>Approval Required</span>
          <small>Enabled reviewed actions</small>
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
          placeholder="Search policies, conditions, or actions"
          value={searchQuery}
          onChange={(event) =>
            setSearchQuery(event.target.value)
          }
        />

        <select
          className="select-input"
          value={statusFilter}
          onChange={(event) =>
            setStatusFilter(event.target.value)
          }
        >
          <option value="all">All Statuses</option>
          <option value="Enabled">Enabled</option>
          <option value="Disabled">Disabled</option>
        </select>

        <select
          className="select-input"
          value={approvalFilter}
          onChange={(event) =>
            setApprovalFilter(event.target.value)
          }
        >
          <option value="all">All Approval Modes</option>
          <option value="Automatic">Automatic</option>
          <option value="Analyst Approval">
            Analyst Approval
          </option>
          <option value="Administrator Approval">
            Administrator Approval
          </option>
        </select>

        <button
          className="btn"
          type="button"
          onClick={resetFilters}
        >
          Reset Filters
        </button>

        <span className="pill blue">
          {visiblePolicies.length} visible
        </span>
      </div>

      <div className="grid two">
        {visiblePolicies.map((policy) => (
          <article
            className="card"
            key={policy.id}
            data-search-record
            data-page-target="response-policies"
          >
            <div className="headline">
              <div>
                <h2>{policy.name}</h2>

                <p className="sub">
                  {policy.id} · Security Management
                </p>
              </div>

              <span
                className={`pill ${statusClass(
                  policy.status,
                )}`}
              >
                {policy.status}
              </span>
            </div>

            <div className="notice">
              <strong>{policy.condition}</strong>

              <div
                className="split-list"
                style={{ marginTop: '14px' }}
              >
                {policy.actions.map((action) => (
                  <span
                    className="pill blue"
                    key={action}
                  >
                    {action}
                  </span>
                ))}
              </div>
            </div>

            <div className="kv">
              <span>Approval Mode</span>

              <strong>
                <span
                  className={`pill ${approvalClass(
                    policy.approvalMode,
                  )}`}
                >
                  {policy.approvalMode}
                </span>
              </strong>
            </div>

            <div className="kv">
              <span>Risk Threshold</span>
              <strong>{policy.riskThreshold} / 100</strong>
            </div>

            <div className="kv">
              <span>Last Updated</span>
              <strong>{policy.lastUpdated}</strong>
            </div>

            <p className="sub">{policy.description}</p>

            <div className="actions-cell">
              <button
                className="btn small"
                type="button"
                onClick={() => openViewModal(policy)}
              >
                View
              </button>

              <button
                className="btn small"
                type="button"
                onClick={() => openEditModal(policy)}
              >
                Edit
              </button>

              <button
                className={
                  policy.status === 'Enabled'
                    ? 'btn small danger'
                    : 'btn small primary'
                }
                type="button"
                onClick={() =>
                  togglePolicyStatus(policy.id)
                }
              >
                {policy.status === 'Enabled'
                  ? 'Disable'
                  : 'Enable'}
              </button>

              <button
                className="btn small danger"
                type="button"
                onClick={() =>
                  openDeleteModal(policy)
                }
              >
                Delete
              </button>
            </div>
          </article>
        ))}

        {visiblePolicies.length === 0 && (
          <div className="card">
            <div className="empty">
              <strong>No response policies found</strong>

              <p className="sub">
                No policies match the current search and
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
          </div>
        )}
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
              onSubmit={savePolicy}
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
                  ? 'Add Response Policy'
                  : `Edit ${selectedPolicy?.id}`}
              </h2>

              <div className="modal-body">
                <p className="sub">
                  {modalMode === 'add'
                    ? 'Create a temporary frontend response policy.'
                    : 'Update the selected response policy.'}
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
                      htmlFor="policyName"
                    >
                      Policy Name
                    </label>

                    <input
                      className="field-input"
                      id="policyName"
                      name="name"
                      value={policyForm.name}
                      onChange={handleFormChange}
                      placeholder="Example: Critical Malware Isolation"
                    />
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="policyApprovalMode"
                    >
                      Approval Mode
                    </label>

                    <select
                      className="select-input"
                      id="policyApprovalMode"
                      name="approvalMode"
                      value={policyForm.approvalMode}
                      onChange={handleFormChange}
                    >
                      <option value="Automatic">
                        Automatic
                      </option>

                      <option value="Analyst Approval">
                        Analyst Approval
                      </option>

                      <option value="Administrator Approval">
                        Administrator Approval
                      </option>
                    </select>
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="policyStatus"
                    >
                      Status
                    </label>

                    <select
                      className="select-input"
                      id="policyStatus"
                      name="status"
                      value={policyForm.status}
                      onChange={handleFormChange}
                    >
                      <option value="Enabled">
                        Enabled
                      </option>

                      <option value="Disabled">
                        Disabled
                      </option>
                    </select>
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="policyRiskThreshold"
                    >
                      Risk Threshold
                    </label>

                    <input
                      className="field-input"
                      id="policyRiskThreshold"
                      name="riskThreshold"
                      type="number"
                      min="0"
                      max="100"
                      value={policyForm.riskThreshold}
                      onChange={handleFormChange}
                    />
                  </div>
                </div>

                <div style={{ marginTop: '16px' }}>
                  <label
                    className="form-label"
                    htmlFor="policyCondition"
                  >
                    Policy Condition
                  </label>

                  <textarea
                    className="textarea-input"
                    id="policyCondition"
                    name="condition"
                    rows={3}
                    value={policyForm.condition}
                    onChange={handleFormChange}
                    placeholder="IF Severity = Critical AND Risk Score >= 90"
                  />
                </div>

                <div style={{ marginTop: '16px' }}>
                  <label
                    className="form-label"
                    htmlFor="policyActions"
                  >
                    Actions
                  </label>

                  <input
                    className="field-input"
                    id="policyActions"
                    name="actions"
                    value={policyForm.actions}
                    onChange={handleFormChange}
                    placeholder="Block IP, Notify Administrator, Create Case"
                  />

                  <p
                    className="sub"
                    style={{
                      marginTop: '8px',
                      fontSize: '12px',
                    }}
                  >
                    Valid actions: {allowedActions.join(', ')}
                  </p>
                </div>

                <div style={{ marginTop: '16px' }}>
                  <label
                    className="form-label"
                    htmlFor="policyDescription"
                  >
                    Description
                  </label>

                  <textarea
                    className="textarea-input"
                    id="policyDescription"
                    name="description"
                    rows={4}
                    value={policyForm.description}
                    onChange={handleFormChange}
                    placeholder="Describe when and why this policy should execute."
                  />
                </div>
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
                    ? 'Add Policy'
                    : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>,
          document.body,
        )}

      {modalMode === 'view' &&
        selectedPolicy &&
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
              aria-label="Response policy details"
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
                    Response Policy
                  </span>

                  <h2>{selectedPolicy.name}</h2>
                </div>

                <span
                  className={`pill ${statusClass(
                    selectedPolicy.status,
                  )}`}
                >
                  {selectedPolicy.status}
                </span>
              </div>

              <div className="modal-body">
                <div className="kv">
                  <span>Policy ID</span>
                  <strong>{selectedPolicy.id}</strong>
                </div>

                <div className="kv">
                  <span>Approval Mode</span>
                  <strong>
                    {selectedPolicy.approvalMode}
                  </strong>
                </div>

                <div className="kv">
                  <span>Risk Threshold</span>
                  <strong>
                    {selectedPolicy.riskThreshold} / 100
                  </strong>
                </div>

                <div className="kv">
                  <span>Last Updated</span>
                  <strong>
                    {selectedPolicy.lastUpdated}
                  </strong>
                </div>

                <div
                  className="card"
                  style={{ marginTop: '16px' }}
                >
                  <h3>Policy Condition</h3>

                  <p className="sub">
                    {selectedPolicy.condition}
                  </p>
                </div>

                <div
                  className="card"
                  style={{ marginTop: '16px' }}
                >
                  <h3>Allowed Actions</h3>

                  <div className="split-list">
                    {selectedPolicy.actions.map(
                      (action) => (
                        <span
                          className="pill blue"
                          key={action}
                        >
                          {action}
                        </span>
                      ),
                    )}
                  </div>
                </div>

                <div
                  className="card"
                  style={{ marginTop: '16px' }}
                >
                  <h3>Description</h3>

                  <p className="sub">
                    {selectedPolicy.description}
                  </p>
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
                  className="btn primary"
                  type="button"
                  onClick={() =>
                    openEditModal(selectedPolicy)
                  }
                >
                  Edit Policy
                </button>

                <button
                  className={
                    selectedPolicy.status === 'Enabled'
                      ? 'btn danger'
                      : 'btn primary'
                  }
                  type="button"
                  onClick={() =>
                    togglePolicyStatus(
                      selectedPolicy.id,
                    )
                  }
                >
                  {selectedPolicy.status === 'Enabled'
                    ? 'Disable Policy'
                    : 'Enable Policy'}
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}

      {modalMode === 'delete' &&
        selectedPolicy &&
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
              aria-label="Delete response policy"
              onClick={(event) =>
                event.stopPropagation()
              }
            >
              <h2>Delete Response Policy</h2>

              <div className="modal-body">
                <p>
                  Delete{' '}
                  <strong>{selectedPolicy.name}</strong>?
                </p>

                <p
                  className="sub"
                  style={{ marginTop: '10px' }}
                >
                  This removes the policy for the current
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
                  onClick={deleteSelectedPolicy}
                >
                  Delete Policy
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}
    </section>
  )
}

export default ResponsePoliciesPage
