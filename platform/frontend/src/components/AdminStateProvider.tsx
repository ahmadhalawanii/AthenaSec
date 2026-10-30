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
import { fromResponsePolicy, toResponsePolicy, toUserRecord } from '../api/adapters'
import type { ApiActionPolicyDocument, ApiUser } from '../api/apiTypes'
import { ApiError, api } from '../api/client'
import { fromConfiguration, toConfiguration, type ApiConfiguration } from '../api/settingsApi'
import { useLiveData } from '../api/liveDataContext'
import { tamperLog, type AuditLinks } from '../data/auditChain'
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
import type { AdminSessionUser, AdminState, LiveUserActions, UserFields } from '../types/adminStateTypes'
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
const NO_AUDIT: AuditLogRecord[] = []
const NO_LINKS: AuditLinks = {}

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

  /*
    Live mode: users and services come from the backend. They replace the
    sample lists whenever the backend sends a new copy. User changes go
    through liveUsers (the backend's /users routes), which audit them.
  */
  const live = useLiveData()
  const isLive = live.mode === 'live'
  const refreshLive = live.refresh

  useEffect(() => {
    if (!isLive || !live.users.items) {
      return
    }

    latest.current = { ...latest.current, users: live.users.items }
    setData(latest.current)
  }, [isLive, live.users.items])

  // Live mode: the backend's configuration, and the version a save must build on
  const configurationVersion = useRef(0)

  useEffect(() => {
    if (!isLive) {
      return undefined
    }

    let cancelled = false

    api<ApiConfiguration>('/configuration')
      .then((doc) => {
        if (!cancelled) {
          configurationVersion.current = doc.version
          latest.current = { ...latest.current, configuration: toConfiguration(doc) }
          setData(latest.current)
        }
      })
      .catch(() => {})

    return () => {
      cancelled = true
    }
  }, [isLive])

  useEffect(() => {
    if (!isLive || !live.services.items) {
      return
    }

    latest.current = { ...latest.current, services: live.services.items }
    setData(latest.current)
  }, [isLive, live.services.items])

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
  const [demoUserId] = useState(
    () => initialUsers.find((record) => record.email === user.email)?.id ?? '',
  )
  // Live mode: the signed-in account in the backend's directory
  const [liveUserId, setLiveUserId] = useState('')
  const liveMatch = isLive ? live.users.items?.find((record) => record.email === user.email)?.id ?? '' : ''

  if (liveMatch && liveMatch !== liveUserId) {
    setLiveUserId(liveMatch)
  }

  const currentUserId = isLive ? liveUserId : demoUserId

  const liveUsers = useMemo<LiveUserActions | null>(() => {
    if (!isLive) {
      return null
    }

    const NOT_SET = 'Not set'
    const body = (fields: UserFields) => ({
      name: fields.name.trim(),
      email: fields.email.trim(),
      role: fields.role,
      department: fields.department.trim() === NOT_SET ? '' : fields.department.trim(),
      phone: fields.phone.trim() === NOT_SET ? '' : fields.phone.trim(),
    })
    const message = (error: unknown) => (error instanceof Error ? error.message : 'The backend refused the change.')
    const path = (userId: string) => `/users/${encodeURIComponent(userId)}`
    type Issued = { user: ApiUser; temporary_password: string; totp_uri: string | null }

    async function attempt(run: () => Promise<unknown>) {
      try {
        await run()
        return null
      } catch (error) {
        return message(error)
      } finally {
        refreshLive()
      }
    }

    return {
      async create(fields, active) {
        try {
          const issued = await api<Issued>('/users', { method: 'POST', body: body(fields) })

          if (!active) {
            await api(`${path(issued.user.user_id)}/status`, { method: 'POST', body: { active: false } })
          }

          return {
            credentials: {
              user: toUserRecord(issued.user),
              temporaryPassword: issued.temporary_password,
              totpUri: issued.totp_uri,
            },
          }
        } catch (error) {
          return { error: message(error) }
        } finally {
          refreshLive()
        }
      },
      update: (userId, fields, active) =>
        attempt(async () => {
          await api(path(userId), { method: 'PUT', body: body(fields) })

          if (active !== null) {
            await api(`${path(userId)}/status`, { method: 'POST', body: { active } })
          }
        }),
      setActive: (userId, active) =>
        attempt(() => api(`${path(userId)}/status`, { method: 'POST', body: { active } })),
      remove: (userId) => attempt(() => api(path(userId), { method: 'DELETE' })),
      async resetMfa(userId) {
        try {
          const issued = await api<{ user: ApiUser; totp_uri: string }>(`${path(userId)}/reset-mfa`, { method: 'POST' })

          return {
            credentials: { user: toUserRecord(issued.user), temporaryPassword: null, totpUri: issued.totp_uri },
          }
        } catch (error) {
          return { error: message(error) }
        } finally {
          refreshLive()
        }
      },
      async resetPassword(userId) {
        try {
          const issued = await api<Issued>(`${path(userId)}/reset-password`, { method: 'POST' })

          return {
            credentials: {
              user: toUserRecord(issued.user),
              temporaryPassword: issued.temporary_password,
              totpUri: null,
            },
          }
        } catch (error) {
          return { error: message(error) }
        }
      },
    }
  }, [isLive, refreshLive])

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
      // Live mode shows the backend's audit trail and its own hash-chain check
      auditLogs: isLive ? live.audit.items ?? NO_AUDIT : auditLogs,
      auditIntegrity: isLive ? live.auditIntegrity : auditIntegrity,
      auditLinks: isLive ? NO_LINKS : auditLinks,
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
      liveUsers,

      async saveResponsePolicy(next) {
        const before = policyRef.current
        const refusal = policyRefusal(next, before)

        if (refusal) {
          return refusal
        }

        const changes = listChanges(before, next)

        // An unchanged save writes nothing and keeps the version
        if (changes.length === 0) {
          return null
        }

        /*
          Live mode: the backend stores the new version, audits it and the agent
          enforces it from the next investigation. The audit event is the
          backend's, so the audit log is fetched again rather than written here.
        */
        if (isLive) {
          const reason = `Updated in the administration console: ${changes.join('; ')}`.slice(0, 500)

          try {
            const saved = await api<ApiActionPolicyDocument>('/policies/actions', {
              method: 'PUT',
              body: { ...fromResponsePolicy(next), base_version: before.version, reason },
            })

            setPolicy(toResponsePolicy(saved))
            refreshLive()

            return null
          } catch (error) {
            if (error instanceof ApiError && error.status === 409) {
              return 'Someone else saved the policy first. Reload the page to see their version, then make your change again.'
            }

            return error instanceof Error ? error.message : 'The policy could not be saved.'
          }
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

      async saveConfiguration(values) {
        const before = latest.current.configuration
        const changes = diffChanges(before, values, CONFIGURATION_FIELDS)

        if (isLive) {
          try {
            const doc = await api<ApiConfiguration>('/configuration', {
              method: 'PUT',
              body: fromConfiguration(values, configurationVersion.current),
            })

            configurationVersion.current = doc.version
            commit({ configuration: toConfiguration(doc) })
            refreshLive()

            return null
          } catch (error) {
            return error instanceof Error ? error.message : 'The configuration could not be saved.'
          }
        }

        commit(
          { configuration: values },
          changes.length > 0
            ? event('System', 'Saved configuration', 'Workspace configuration',
                'Workspace configuration was saved through the AthenaSec administration console.',
                changes, { Organization: values.organization })
            : undefined,
        )

        return null
      },
    }
  }, [data, responsePolicy, policyRef, setPolicy, auditLogs, auditIntegrity, auditLinks, recordedLogs, tamperedIds, currentUserId, user.name, user.role, isLive, live.audit.items, live.auditIntegrity, refreshLive, liveUsers])

  return <AdminContext.Provider value={value}>{children}</AdminContext.Provider>
}

export default AdminStateProvider
