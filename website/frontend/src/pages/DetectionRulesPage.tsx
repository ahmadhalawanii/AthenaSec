import {
  useMemo,
  useState,
  type ChangeEvent,
  type FormEvent,
} from 'react'
import { createPortal } from 'react-dom'
import type {
  DetectionRule,
  ModalMode,
  RuleFormState,
  RuleStatus,
} from '../types/detectionRulesTypes'

import { initialRules, emptyRuleForm } from '../data/detectionRulesData'


function statusClass(status: RuleStatus) {
  return status === 'Enabled' ? 'ok' : 'muted'
}

function severityClass(severity: DetectionRule['severity']) {
  if (severity === 'Critical') {
    return 'danger'
  }

  if (severity === 'High') {
    return 'warn'
  }

  if (severity === 'Medium') {
    return 'blue'
  }

  return 'muted'
}

function DetectionRulesPage() {
  const [rules, setRules] =
    useState<DetectionRule[]>(initialRules)

  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [categoryFilter, setCategoryFilter] = useState('all')

  const [modalMode, setModalMode] =
    useState<ModalMode>(null)

  const [selectedRule, setSelectedRule] =
    useState<DetectionRule | null>(null)

  const [ruleForm, setRuleForm] =
    useState<RuleFormState>(emptyRuleForm)

  const [formError, setFormError] = useState('')

  const visibleRules = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase()

    return rules.filter((rule) => {
      const matchesSearch =
        normalizedQuery === '' ||
        rule.id.toLowerCase().includes(normalizedQuery) ||
        rule.name.toLowerCase().includes(normalizedQuery) ||
        rule.category.toLowerCase().includes(normalizedQuery) ||
        rule.threshold.toLowerCase().includes(normalizedQuery) ||
        rule.policy.toLowerCase().includes(normalizedQuery) ||
        rule.severity.toLowerCase().includes(normalizedQuery) ||
        rule.mitre.toLowerCase().includes(normalizedQuery) ||
        rule.dataSource.toLowerCase().includes(normalizedQuery)

      const matchesStatus =
        statusFilter === 'all' ||
        rule.status === statusFilter

      const matchesCategory =
        categoryFilter === 'all' ||
        rule.category === categoryFilter

      return (
        matchesSearch &&
        matchesStatus &&
        matchesCategory
      )
    })
  }, [rules, searchQuery, statusFilter, categoryFilter])

  const enabledCount = rules.filter(
    (rule) => rule.status === 'Enabled',
  ).length

  const disabledCount = rules.filter(
    (rule) => rule.status === 'Disabled',
  ).length

  function resetFilters() {
    setSearchQuery('')
    setStatusFilter('all')
    setCategoryFilter('all')
  }

  function closeModal() {
    setModalMode(null)
    setSelectedRule(null)
    setRuleForm(emptyRuleForm)
    setFormError('')
  }

  function openAddModal() {
    setSelectedRule(null)
    setRuleForm(emptyRuleForm)
    setFormError('')
    setModalMode('add')
  }

  function openEditModal(rule: DetectionRule) {
    setSelectedRule(rule)

    setRuleForm({
      name: rule.name,
      category: rule.category,
      threshold: rule.threshold,
      policy: rule.policy,
      status: rule.status,
      severity: rule.severity,
      mitre: rule.mitre,
      description: rule.description,
      dataSource: rule.dataSource,
    })

    setFormError('')
    setModalMode('edit')
  }

  function openViewModal(rule: DetectionRule) {
    setSelectedRule(rule)
    setModalMode('view')
  }

  function openDeleteModal(rule: DetectionRule) {
    setSelectedRule(rule)
    setModalMode('delete')
  }

  function handleFormChange(
    event:
      | ChangeEvent<HTMLInputElement>
      | ChangeEvent<HTMLSelectElement>
      | ChangeEvent<HTMLTextAreaElement>,
  ) {
    const { name, value } = event.target

    setRuleForm((currentForm) => ({
      ...currentForm,
      [name]: value,
    }))
  }

  function validateRuleForm() {
    if (!ruleForm.name.trim()) {
      return 'Rule name is required.'
    }

    if (!ruleForm.threshold.trim()) {
      return 'Detection threshold is required.'
    }

    if (!ruleForm.policy.trim()) {
      return 'Response policy is required.'
    }

    if (!ruleForm.mitre.trim()) {
      return 'MITRE ATT&CK mapping is required.'
    }

    if (!ruleForm.description.trim()) {
      return 'Rule description is required.'
    }

    if (!ruleForm.dataSource.trim()) {
      return 'Data source is required.'
    }

    return ''
  }

  function saveRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    const validationError = validateRuleForm()

    if (validationError) {
      setFormError(validationError)
      return
    }

    if (modalMode === 'add') {
      const highestRuleNumber = rules.reduce(
        (highestNumber, rule) => {
          const ruleNumber = Number(
            rule.id.replace('RULE-', ''),
          )

          return Number.isNaN(ruleNumber)
            ? highestNumber
            : Math.max(highestNumber, ruleNumber)
        },
        0,
      )

      const newRule: DetectionRule = {
        id: `RULE-${String(
          highestRuleNumber + 1,
        ).padStart(3, '0')}`,
        name: ruleForm.name.trim(),
        category: ruleForm.category,
        threshold: ruleForm.threshold.trim(),
        policy: ruleForm.policy.trim(),
        status: ruleForm.status,
        severity: ruleForm.severity,
        mitre: ruleForm.mitre.trim(),
        description: ruleForm.description.trim(),
        dataSource: ruleForm.dataSource.trim(),
        lastUpdated: 'Just now',
      }

      setRules((currentRules) => [
        ...currentRules,
        newRule,
      ])

      closeModal()
      return
    }

    if (modalMode === 'edit' && selectedRule) {
      setRules((currentRules) =>
        currentRules.map((rule) =>
          rule.id === selectedRule.id
            ? {
                ...rule,
                name: ruleForm.name.trim(),
                category: ruleForm.category,
                threshold: ruleForm.threshold.trim(),
                policy: ruleForm.policy.trim(),
                status: ruleForm.status,
                severity: ruleForm.severity,
                mitre: ruleForm.mitre.trim(),
                description:
                  ruleForm.description.trim(),
                dataSource: ruleForm.dataSource.trim(),
                lastUpdated: 'Just now',
              }
            : rule,
        ),
      )

      closeModal()
    }
  }

  function toggleRuleStatus(ruleId: string) {
    setRules((currentRules) =>
      currentRules.map((rule) =>
        rule.id === ruleId
          ? {
              ...rule,
              status:
                rule.status === 'Enabled'
                  ? 'Disabled'
                  : 'Enabled',
              lastUpdated: 'Just now',
            }
          : rule,
      ),
    )
  }

  function deleteSelectedRule() {
    if (!selectedRule) {
      return
    }

    setRules((currentRules) =>
      currentRules.filter(
        (rule) => rule.id !== selectedRule.id,
      ),
    )

    closeModal()
  }

  return (
    <section
      className="page active"
      data-page="detection-rules"
      data-page-name="Detection Rules"
      data-search-page
    >
      <div className="headline">
        <div>
          <h1>Detection Rules</h1>

          <p className="sub">
            Add, edit, delete, enable, disable, search,
            and filter detection logic.
          </p>
        </div>

        <button
          className="btn primary"
          type="button"
          onClick={openAddModal}
        >
          + Add Rule
        </button>
      </div>

      <div className="grid stats">
        <div className="stat">
          <strong>{rules.length}</strong>
          <span>Total Rules</span>
          <small>Current frontend rules</small>
        </div>

        <div className="stat">
          <strong>{enabledCount}</strong>
          <span>Enabled</span>
          <small>Actively detecting</small>
        </div>

        <div className="stat">
          <strong>{disabledCount}</strong>
          <span>Disabled</span>
          <small>Not currently active</small>
        </div>

        <div className="stat">
          <strong>
            {
              rules.filter(
                (rule) =>
                  rule.severity === 'Critical',
              ).length
            }
          </strong>

          <span>Critical Rules</span>
          <small>Highest severity logic</small>
        </div>
      </div>

      <div
        className="toolbar"
        style={{ marginTop: '18px' }}
      >
        <input
          className="field-input"
          id="ruleSearch"
          type="search"
          placeholder="Search rules"
          value={searchQuery}
          onChange={(event) =>
            setSearchQuery(event.target.value)
          }
        />

        <select
          className="select-input"
          id="ruleStatus"
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
          value={categoryFilter}
          onChange={(event) =>
            setCategoryFilter(event.target.value)
          }
        >
          <option value="all">All Categories</option>
          <option value="Authentication">
            Authentication
          </option>
          <option value="Privilege Escalation">
            Privilege Escalation
          </option>
          <option value="Network">Network</option>
          <option value="Endpoint">Endpoint</option>
          <option value="Malware">Malware</option>
        </select>

        <button
          className="btn"
          type="button"
          onClick={resetFilters}
        >
          Reset Filters
        </button>

        <span className="pill blue">
          {visibleRules.length} visible
        </span>
      </div>

      <div className="card">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>Category</th>
                <th>Threshold</th>
                <th>Policy</th>
                <th>Actions</th>
                <th>Status</th>
              </tr>
            </thead>

            <tbody id="ruleRows">
              {visibleRules.map((rule) => (
                <tr
                  key={rule.id}
                  className="data-row"
                  data-search-record
                  data-page-target="detection-rules"
                  data-status={rule.status}
                >
                  <td>
                    <strong>{rule.name}</strong>

                    <div
                      className="sub"
                      style={{
                        marginTop: '4px',
                        fontSize: '12px',
                      }}
                    >
                      {rule.id} · {rule.severity}
                    </div>
                  </td>

                  <td>{rule.category}</td>
                  <td>{rule.threshold}</td>
                  <td>{rule.policy}</td>

                  <td className="actions-cell">
                    <button
                      className="btn small"
                      type="button"
                      onClick={() =>
                        openViewModal(rule)
                      }
                    >
                      View
                    </button>

                    <button
                      className="btn small"
                      type="button"
                      onClick={() =>
                        openEditModal(rule)
                      }
                    >
                      Edit
                    </button>

                    <button
                      className={
                        rule.status === 'Enabled'
                          ? 'btn small danger'
                          : 'btn small primary'
                      }
                      type="button"
                      onClick={() =>
                        toggleRuleStatus(rule.id)
                      }
                    >
                      {rule.status === 'Enabled'
                        ? 'Disable'
                        : 'Enable'}
                    </button>

                    <button
                      className="btn small danger"
                      type="button"
                      onClick={() =>
                        openDeleteModal(rule)
                      }
                    >
                      Delete
                    </button>
                  </td>

                  <td className="rule-status">
                    <span
                      className={`pill ${statusClass(
                        rule.status,
                      )}`}
                    >
                      {rule.status}
                    </span>
                  </td>
                </tr>
              ))}

              {visibleRules.length === 0 && (
                <tr>
                  <td colSpan={6}>
                    <div className="empty">
                      <strong>
                        No detection rules found
                      </strong>

                      <p className="sub">
                        No rules match the current search
                        and filters.
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
              onSubmit={saveRule}
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
                  ? 'Add Detection Rule'
                  : `Edit ${selectedRule?.id}`}
              </h2>

              <div className="modal-body">
                <p className="sub">
                  {modalMode === 'add'
                    ? 'Create a temporary frontend detection rule.'
                    : 'Update the selected detection rule.'}
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
                      htmlFor="ruleName"
                    >
                      Rule Name
                    </label>

                    <input
                      className="field-input"
                      id="ruleName"
                      name="name"
                      value={ruleForm.name}
                      onChange={handleFormChange}
                      placeholder="Example: Suspicious SSH Login"
                    />
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="ruleCategory"
                    >
                      Category
                    </label>

                    <select
                      className="select-input"
                      id="ruleCategory"
                      name="category"
                      value={ruleForm.category}
                      onChange={handleFormChange}
                    >
                      <option value="Authentication">
                        Authentication
                      </option>

                      <option value="Privilege Escalation">
                        Privilege Escalation
                      </option>

                      <option value="Network">
                        Network
                      </option>

                      <option value="Endpoint">
                        Endpoint
                      </option>

                      <option value="Malware">
                        Malware
                      </option>
                    </select>
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="ruleThreshold"
                    >
                      Threshold
                    </label>

                    <input
                      className="field-input"
                      id="ruleThreshold"
                      name="threshold"
                      value={ruleForm.threshold}
                      onChange={handleFormChange}
                      placeholder="Example: 10 events / 5 min"
                    />
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="ruleSeverity"
                    >
                      Severity
                    </label>

                    <select
                      className="select-input"
                      id="ruleSeverity"
                      name="severity"
                      value={ruleForm.severity}
                      onChange={handleFormChange}
                    >
                      <option value="Low">Low</option>
                      <option value="Medium">
                        Medium
                      </option>
                      <option value="High">High</option>
                      <option value="Critical">
                        Critical
                      </option>
                    </select>
                  </div>

                  <div>
                    <label
                      className="form-label"
                      htmlFor="ruleStatusInput"
                    >
                      Status
                    </label>

                    <select
                      className="select-input"
                      id="ruleStatusInput"
                      name="status"
                      value={ruleForm.status}
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
                      htmlFor="ruleMitre"
                    >
                      MITRE ATT&amp;CK
                    </label>

                    <input
                      className="field-input"
                      id="ruleMitre"
                      name="mitre"
                      value={ruleForm.mitre}
                      onChange={handleFormChange}
                      placeholder="Example: T1110 - Brute Force"
                    />
                  </div>
                </div>

                <div style={{ marginTop: '16px' }}>
                  <label
                    className="form-label"
                    htmlFor="rulePolicy"
                  >
                    Response Policy
                  </label>

                  <input
                    className="field-input"
                    id="rulePolicy"
                    name="policy"
                    value={ruleForm.policy}
                    onChange={handleFormChange}
                    placeholder="Example: Critical Host Isolation"
                  />
                </div>

                <div style={{ marginTop: '16px' }}>
                  <label
                    className="form-label"
                    htmlFor="ruleDataSource"
                  >
                    Data Source
                  </label>

                  <input
                    className="field-input"
                    id="ruleDataSource"
                    name="dataSource"
                    value={ruleForm.dataSource}
                    onChange={handleFormChange}
                    placeholder="Example: Wazuh authentication logs"
                  />
                </div>

                <div style={{ marginTop: '16px' }}>
                  <label
                    className="form-label"
                    htmlFor="ruleDescription"
                  >
                    Description
                  </label>

                  <textarea
                    className="textarea-input"
                    id="ruleDescription"
                    name="description"
                    value={ruleForm.description}
                    onChange={handleFormChange}
                    rows={4}
                    placeholder="Describe what the rule detects."
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
                    ? 'Add Rule'
                    : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>,
          document.body,
        )}

      {modalMode === 'view' &&
        selectedRule &&
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
              aria-label="Detection rule details"
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
                    Detection Rule
                  </span>

                  <h2>{selectedRule.name}</h2>
                </div>

                <span
                  className={`pill ${statusClass(
                    selectedRule.status,
                  )}`}
                >
                  {selectedRule.status}
                </span>
              </div>

              <div className="modal-body">
                <div className="kv">
                  <span>Rule ID</span>
                  <strong>{selectedRule.id}</strong>
                </div>

                <div className="kv">
                  <span>Category</span>
                  <strong>
                    {selectedRule.category}
                  </strong>
                </div>

                <div className="kv">
                  <span>Severity</span>

                  <strong>
                    <span
                      className={`pill ${severityClass(
                        selectedRule.severity,
                      )}`}
                    >
                      {selectedRule.severity}
                    </span>
                  </strong>
                </div>

                <div className="kv">
                  <span>Threshold</span>
                  <strong>
                    {selectedRule.threshold}
                  </strong>
                </div>

                <div className="kv">
                  <span>Response Policy</span>
                  <strong>{selectedRule.policy}</strong>
                </div>

                <div className="kv">
                  <span>MITRE ATT&amp;CK</span>
                  <strong>{selectedRule.mitre}</strong>
                </div>

                <div className="kv">
                  <span>Data Source</span>
                  <strong>
                    {selectedRule.dataSource}
                  </strong>
                </div>

                <div className="kv">
                  <span>Last Updated</span>
                  <strong>
                    {selectedRule.lastUpdated}
                  </strong>
                </div>

                <div
                  className="card"
                  style={{ marginTop: '16px' }}
                >
                  <h3>Description</h3>

                  <p className="sub">
                    {selectedRule.description}
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
                    openEditModal(selectedRule)
                  }
                >
                  Edit Rule
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}

      {modalMode === 'delete' &&
        selectedRule &&
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
              aria-label="Delete detection rule"
              onClick={(event) =>
                event.stopPropagation()
              }
            >
              <h2>Delete Detection Rule</h2>

              <div className="modal-body">
                <p>
                  Delete{' '}
                  <strong>{selectedRule.name}</strong>?
                </p>

                <p
                  className="sub"
                  style={{ marginTop: '10px' }}
                >
                  This removes the rule for the current
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
                  onClick={deleteSelectedRule}
                >
                  Delete Rule
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}
    </section>
  )
}

export default DetectionRulesPage
