import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import {
  ADMIN_CONSOLE_IP,
  auditLogs as seedAuditLogs,
  auditTimestamp,
  createdChanges,
  deletedChanges,
  diffChanges,
  auditNumber,
  takeAuditId,
  type ChangeLabels,
} from '../data/auditLogsData'
import { tamperLog } from '../data/auditChain'
import { demoAuditEvent } from '../data/auditDemoEvents'
import { initialConfiguration } from '../data/configurationData'
import { listChanges, policyRefusal } from '../data/policyEngine'
import { initialServicePanel } from '../data/servicePanelData'
import { initialServices } from '../data/systemHealthData'
import { initialUsers } from '../data/userManagementData'
import { AdminContext } from '../hooks/adminContext'
import { useAuditChain } from '../hooks/useAuditChain'
import { useResponsePolicy } from '../hooks/useResponsePolicy'
import { useResponseState } from '../hooks/useResponseState'
import type { AdminSessionUser, AdminState } from '../types/adminStateTypes'
import type { AuditCategory, AuditLogRecord } from '../types/auditLogsTypes'
import type { ConfigurationValues } from '../types/configurationTypes'
import type { ResponsePolicy } from '../types/responsePoliciesTypes'
import type { ServicePanelState } from '../types/servicePanelTypes'
import type { ServiceRecord } from '../types/systemHealthTypes'
import type { UserRecord } from '../types/userManagementTypes'

type AdminStateProviderProps = {
  user: AdminSessionUser
  children: ReactNode
}

type AdminData = {
  users: UserRecord[]
  services: ServiceRecord[]
  // The Service Panel's demo snapshot (read only: nothing on that page changes it)
  servicePanel: ServicePanelState
  configuration: ConfigurationValues
  // This session's audit events, newest first
  sessionAudit: AuditLogRecord[]
}

const seed: AdminData = {
  users: initialUsers,
  services: initialServices,
  servicePanel: initialServicePanel,
  configuration: initialConfiguration,
  sessionAudit: [],
}

// Fields whose changes are written to the audit log, with their labels
const USER_FIELDS: ChangeLabels<UserRecord> = {
  name: 'Name',
  email: 'Email',
  role: 'Role',
  status: 'Status',
  department: 'Department',
  phone: 'Phone',
  mfaEnabled: 'MFA',
}

const CONFIGURATION_FIELDS: ChangeLabels<ConfigurationValues> = {
  organization: 'Organization',
  workspace: 'Workspace',
  correlationWindowMinutes: 'Correlation window (minutes)',
  criticalRiskThreshold: 'Critical risk threshold',
  loggingDestination: 'Logging destination',
  loggingMode: 'Logging mode',
  hotStorageDays: 'Hot storage (days)',
  auditRetentionDays: 'Audit retention (days)',
  criticalAlertNotification: 'Critical alert notification',
}

const SERVICE_FIELDS: ChangeLabels<ServiceRecord> = {
  status: 'status',
  latency: 'latency (ms)',
  lastCheck: 'last check',
}

// "USR-009" follows the highest USR- number in use
function nextId(prefix: string, ids: string[]) {
  const highest = ids.reduce((max, id) => {
    const number = Number(id.replace(`${prefix}-`, ''))
    return Number.isNaN(number) ? max : Math.max(max, number)
  }, 0)

  return `${prefix}-${String(highest + 1).padStart(3, '0')}`
}

/*
  Simulated admin changes, held in memory like the rest of the prototype
  (they reset on reload). The seed data stays untouched. Every change is
  also written to the audit log, with old → new values.

  Actions read the latest data from a ref, so a change made from a timer
  (sync, service check) never works from a stale copy.
*/
function AdminStateProvider({ user, children }: AdminStateProviderProps) {
  const { auditEvents: responseAudit, now: demoNow } = useResponseState()
  // The one response policy lives above the approval flow, so the flow reads it too
  const { policy: responsePolicy, policyRef, setPolicy } = useResponsePolicy()
  const [data, setData] = useState<AdminData>(seed)
  const latest = useRef<AdminData>(seed)

  // Admin events are stamped from the demo clock, read when the change is made
  const demoNowRef = useRef(demoNow)

  useEffect(() => {
    demoNowRef.current = demoNow
  }, [demoNow])

  // Admin events and approval-flow events share one numbering, newest first
  const recordedLogs = useMemo(
    () => [
      ...[...data.sessionAudit, ...responseAudit].sort((a, b) => auditNumber(b) - auditNumber(a)),
      ...seedAuditLogs,
    ],
    [data.sessionAudit, responseAudit],
  )

  // Demo: records whose stored content was altered after they were hashed (the hashes stay as recorded)
  const [tamperedIds, setTamperedIds] = useState<string[]>([])
  const auditLogs = useMemo(
    () => recordedLogs.map((log) => (tamperedIds.includes(log.id) ? tamperLog(log) : log)),
    [recordedLogs, tamperedIds],
  )
  const { integrity: auditIntegrity, links: auditLinks } = useAuditChain(auditLogs)

  // Matched once by email, so a self edit that changes the email still counts as self
  const [currentUserId] = useState(
    () => initialUsers.find((record) => record.email === user.email)?.id ?? '',
  )

  const value = useMemo<AdminState>(() => {
    function commit(next: Partial<AdminData>, audit?: Omit<AuditLogRecord, 'id' | 'timestamp' | 'user' | 'role' | 'result' | 'sourceIp'>) {
      const current = latest.current
      const updated: AdminData = { ...current, ...next }

      if (audit) {
        updated.sessionAudit = [
          {
            id: takeAuditId(),
            timestamp: auditTimestamp(demoNowRef.current),
            user: user.name,
            role: user.role,
            result: 'Success',
            sourceIp: ADMIN_CONSOLE_IP,
            ...audit,
          },
          ...current.sessionAudit,
        ]
      }

      latest.current = updated
      setData(updated)
    }

    function event(
      category: AuditCategory,
      action: string,
      target: string,
      description: string,
      changes: string[],
      metadata: Record<string, string>,
    ) {
      return { category, action, target, description, changes, metadata }
    }

    const userTarget = (record: UserRecord) => `${record.id} · ${record.name}`

    return {
      responsePolicy,
      users: data.users,
      services: data.services,
      servicePanel: data.servicePanel,
      configuration: data.configuration,
      auditLogs,
      auditIntegrity,
      auditLinks,
      alteredAuditIds: tamperedIds,
      // Demo controls: Administrator only, and each use is a Demo event in the trail
      tamperAudit(id) {
        if (user.role !== 'Administrator' || tamperedIds.includes(id) || !recordedLogs.some((log) => log.id === id)) {
          return
        }

        commit({}, demoAuditEvent('tamper', id))
        setTamperedIds((current) => [...current, id])
      },
      restoreAudit(id) {
        if (user.role !== 'Administrator' || !tamperedIds.includes(id)) {
          return
        }

        commit({}, demoAuditEvent('restore', id))
        setTamperedIds((current) => current.filter((item) => item !== id))
      },
      currentUserId,

      saveResponsePolicy(next) {
        const before = policyRef.current
        const refusal = policyRefusal(next)

        if (refusal) {
          return refusal
        }

        const changes = listChanges(before, next)

        // An unchanged save writes nothing and keeps the version
        if (changes.length === 0) {
          return null
        }

        // Every audited change makes a new version
        const saved: ResponsePolicy = { ...next, version: before.version + 1 }
        setPolicy(saved)
        commit(
          {},
          event('Response Policy', 'Updated response policy', 'Response policy',
            `The response policy was updated through the AthenaSec administration console (version ${before.version} → ${saved.version}).`,
            changes, { 'Policy Version': String(saved.version) }),
        )

        return null
      },

      saveUser(record) {
        const { users } = latest.current
        const before = users.find((item) => item.id === record.id)

        if (!before) {
          commit(
            { users: [...users, record] },
            event('User Management', 'Created user account', userTarget(record),
              `A new ${record.role.toLowerCase()} account was created for ${record.name}.`,
              createdChanges(record, USER_FIELDS), { 'User ID': record.id }),
          )
          return true
        }

        // Your own role and status can only be changed by another administrator
        const after = before.id === currentUserId
          ? { ...record, role: before.role, status: before.status }
          : record
        const changes = diffChanges(before, after, USER_FIELDS)
        commit(
          { users: users.map((item) => (item.id === record.id ? after : item)) },
          changes.length > 0
            ? event('User Management', 'Updated user account', userTarget(after),
                `The account for ${after.name} was updated through the AthenaSec administration console.`,
                changes, { 'User ID': after.id })
            : undefined,
        )
        return true
      },

      toggleUserStatus(userId) {
        const { users } = latest.current
        const before = users.find((item) => item.id === userId)

        if (!before || before.id === currentUserId) {
          return false
        }

        const after: UserRecord = {
          ...before,
          status: before.status === 'Active' ? 'Suspended' : 'Active',
        }
        commit(
          { users: users.map((item) => (item.id === userId ? after : item)) },
          event('User Management',
            after.status === 'Suspended' ? 'Suspended user account' : 'Activated user account',
            userTarget(after),
            `The account for ${after.name} was ${after.status === 'Suspended' ? 'suspended' : 'activated'}.`,
            diffChanges(before, after, USER_FIELDS), { 'User ID': after.id }),
        )
        return true
      },

      requireMfa(userId) {
        const { users } = latest.current
        const before = users.find((item) => item.id === userId)

        if (!before || before.mfaEnabled) {
          return false
        }

        const after: UserRecord = { ...before, mfaEnabled: true }
        commit(
          { users: users.map((item) => (item.id === userId ? after : item)) },
          event('User Management', 'Required MFA for user account', userTarget(after),
            `Multi-factor authentication was turned on for ${after.name}.`,
            diffChanges(before, after, USER_FIELDS), { 'User ID': after.id }),
        )
        return true
      },

      deleteUser(userId) {
        const { users } = latest.current
        const before = users.find((item) => item.id === userId)

        if (!before || before.id === currentUserId) {
          return false
        }

        commit(
          { users: users.filter((item) => item.id !== userId) },
          event('User Management', 'Deleted user account', userTarget(before),
            `The account for ${before.name} was deleted.`,
            deletedChanges(before, USER_FIELDS), { 'User ID': before.id }),
        )
        return true
      },

      resetPassword(userId) {
        const target = latest.current.users.find((item) => item.id === userId)

        if (!target) {
          return
        }

        commit(
          {},
          event('User Management', 'Reset user password', userTarget(target),
            `A temporary password was issued for ${target.name} (simulated, nothing is sent).`,
            ['Password: Current password → Temporary password'], { 'User ID': target.id }),
        )
      },

      nextUserId: () => nextId('USR', latest.current.users.map((record) => record.id)),

      updateServices(update, label) {
        const before = latest.current.services
        const services = update(before)
        const changes = services.flatMap((service) => {
          const old = before.find((item) => item.id === service.id)
          return old
            ? diffChanges(old, service, SERVICE_FIELDS).map((line) => `${service.name} ${line}`)
            : []
        })
        const checked = label === 'check'
          ? services.find((service, index) => service !== before[index])
          : undefined

        commit(
          { services },
          changes.length > 0
            ? event('System',
                label === 'refresh' ? 'Refreshed system health' : label === 'check' ? 'Checked service' : 'Checked all services',
                checked ? `${checked.id} · ${checked.name}` : `${services.length} monitored services`,
                label === 'refresh'
                  ? 'System health metrics and service latencies were refreshed.'
                  : 'A simulated health check was run from the administration console.',
                changes,
                checked ? { 'Service ID': checked.id } : { Services: String(services.length) })
            : undefined,
        )
        return services
      },

      saveConfiguration(values) {
        const before = latest.current.configuration
        const changes = diffChanges(before, values, CONFIGURATION_FIELDS)

        commit(
          { configuration: values },
          changes.length > 0
            ? event('System', 'Saved configuration', 'Workspace configuration',
                'Workspace configuration was saved through the AthenaSec administration console.',
                changes, { Organization: values.organization })
            : undefined,
        )
      },
    }
  }, [data, responsePolicy, policyRef, setPolicy, auditLogs, auditIntegrity, auditLinks, recordedLogs, tamperedIds, currentUserId, user.name, user.role])

  return <AdminContext.Provider value={value}>{children}</AdminContext.Provider>
}

export default AdminStateProvider
