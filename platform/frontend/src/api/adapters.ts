/*
  Turns backend records (apiTypes.ts) into the shapes the pages already
  use (src/types). Anything the backend does not store yet gets a plain,
  honest default ("Unassigned", "Not recorded") rather than a made-up value.
*/

import type { AlertRecord, RiskBand } from '../types/alertsTypes'
import type { AuditCategory, AuditLogRecord, AuditResult } from '../types/auditLogsTypes'
import type { CaseRecord, CaseSeverity } from '../types/casesTypes'
import type { CheckKey } from '../types/servicePanelTypes'
import type { ServiceRecord, ServiceStatus } from '../types/systemHealthTypes'
import type { ActionType, ExecutionRecord, TimelineItem } from '../types/incidentResponseTypes'
import type { ResponsePolicy } from '../types/responsePoliciesTypes'
import type { UserRecord } from '../types/userManagementTypes'

import type {
  ApiActionPolicyContent,
  ApiActionPolicyDocument,
  ApiAlert,
  ApiAuditEvent,
  ApiCase,
  ApiHealthService,
  ApiResponseRun,
  ApiRiskBand,
  ApiUser,
} from './apiTypes'

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

function pad(value: number) {
  return String(value).padStart(2, '0')
}

// "Today, 14:32", "Yesterday, 09:10" or "21 Oct, 18:05", in the viewer's time zone
export function friendlyTime(iso: string | null | undefined): string {
  if (!iso) {
    return 'Not recorded'
  }

  const date = new Date(iso)

  if (Number.isNaN(date.getTime())) {
    return 'Not recorded'
  }

  const clock = `${pad(date.getHours())}:${pad(date.getMinutes())}`
  const today = new Date()
  const yesterday = new Date(today)
  yesterday.setDate(today.getDate() - 1)

  if (date.toDateString() === today.toDateString()) {
    return `Today, ${clock}`
  }

  if (date.toDateString() === yesterday.toDateString()) {
    return `Yesterday, ${clock}`
  }

  return `${date.getDate()} ${MONTHS[date.getMonth()]}, ${clock}`
}

// "2026-10-24 13:10:05", the Audit Logs page's timestamp format
function auditTimestamp(iso: string): string {
  const date = new Date(iso)

  if (Number.isNaN(date.getTime())) {
    return iso
  }

  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null
}

function titleCase(value: string) {
  return value
    .split('_')
    .map((word) => (word ? word[0].toUpperCase() + word.slice(1) : word))
    .join(' ')
}

function bandToSeverity(band: ApiRiskBand): AlertRecord['severity'] {
  return band === 'critical' ? 'Critical' : band === 'high' ? 'High' : band === 'medium' ? 'Medium' : 'Low'
}

function attackGroup(classification: string): AlertRecord['attackGroup'] {
  if (classification === 'brute_force') {
    return 'Brute Force'
  }

  if (classification === 'privilege_escalation' || classification === 'privilege_misuse') {
    return 'Privilege Escalation'
  }

  return 'Other'
}

export function toAlertRecord(alert: ApiAlert): AlertRecord {
  const meta = alert.alert_metadata ?? {}
  const mitre = Array.isArray(meta.mitre_ids) ? (meta.mitre_ids as string[]).join(', ') : ''
  const rule = text(meta.rule_description)
  const confidence = alert.ml_prediction?.confidence
  const risk = alert.risk_assessment
  const reasons = (risk.factors ?? []).map((factor) => factor.reason).filter(Boolean)

  return {
    id: alert.alert_id,
    severity: bandToSeverity(risk.band),
    attackGroup: attackGroup(alert.classification),
    attackType: rule ?? titleCase(alert.classification),
    sourceIp: text(meta.source_ip) ?? text(meta.srcip) ?? 'Not recorded',
    destinationIp: text(meta.destination_ip) ?? text(meta.agent_ip) ?? 'Not recorded',
    endpoint: text(meta.agent_name) ?? 'Not recorded',
    risk: risk.score,
    riskBand: risk.band as RiskBand,
    status: alert.analyst_status === 'closed' ? 'Closed' : 'Open',
    assignedAnalyst: alert.assigned_analyst ?? 'Unassigned',
    time: friendlyTime(alert.observed_at),
    summary: rule
      ? `${rule} Classified as ${titleCase(alert.classification).toLowerCase()}.`
      : `Classified as ${titleCase(alert.classification).toLowerCase()}.`,
    reasoning: reasons.length
      ? reasons.join(' ')
      : `Risk ${risk.score} (${risk.band}).`,
    mitre: mitre || 'Not mapped',
    explanation:
      confidence !== undefined && alert.ml_prediction?.classification !== 'unknown'
        ? `The ML classifier rated this ${titleCase(alert.ml_prediction?.classification ?? '').toLowerCase()} with confidence ${confidence.toFixed(2)}.`
        : 'Assessed by the agent from the alert and its evidence.',
  }
}

export function toCaseRecord(item: ApiCase): CaseRecord {
  const band = item.risk_band ?? 'medium'
  const severity: CaseSeverity = band === 'critical' ? 'Critical' : band === 'high' ? 'High' : 'Medium'

  return {
    id: item.case_id,
    sourceAlert: item.alert_id ?? 'Not linked',
    severity,
    status: item.status === 'closed' || item.status === 'resolved' ? 'Closed' : 'Open',
    assignedAnalyst: item.assigned_analyst ?? 'Unassigned',
    attackType: item.classification ? titleCase(item.classification) : 'Not classified',
    endpoint: item.endpoint ?? 'Not recorded',
    sourceIp: item.source_ip ?? 'Not recorded',
    riskScore: item.risk_score ?? 0,
    createdAt: friendlyTime(item.created_at),
    lastUpdated: friendlyTime(item.updated_at),
    summary: item.summary ?? item.reason,
    evidence: item.evidence.map((entry) => entry.content),
    recommendedActions: item.recommended_actions
      .slice()
      .sort((a, b) => a.position - b.position)
      .map((action) => ({ label: action.label, done: action.done, approvalId: action.approval_id ?? undefined, position: action.position })),
    mitre: item.mitre_ids.join(', ') || 'Not mapped',
    timeline: item.timeline
      .slice()
      .sort((a, b) => a.seq - b.seq)
      .map((entry) => ({
        time: friendlyTime(entry.occurred_at).replace(/^Today, /, ''),
        title: entry.title,
        description: entry.description,
        failed: entry.failed || undefined,
      })),
  }
}

export function toUserRecord(user: ApiUser): UserRecord {
  return {
    id: user.user_id,
    name: user.name,
    email: user.email,
    role: user.role,
    status: user.active ? 'Active' : 'Suspended',
    department: user.department || 'Not set',
    phone: user.phone || 'Not set',
    mfaEnabled: user.mfa_enabled,
    lastLogin: user.last_login_at ? friendlyTime(user.last_login_at) : 'Never',
    createdAt: user.created_at ? user.created_at.slice(0, 10) : 'Not recorded',
  }
}

const SERVICE_STATUS: Record<string, ServiceStatus> = {
  up: 'Running',
  degraded: 'Degraded',
  down: 'Failed',
  starting: 'Starting',
  unconfigured: 'Unverified',
}

function secondsAgo(iso: string | null): string {
  if (!iso) {
    return 'Not checked'
  }

  const seconds = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))

  return seconds < 60 ? `${seconds} seconds ago` : `${Math.round(seconds / 60)} minutes ago`
}

// Backend checks that are also Service Panel checks (the services on the VM)
const PANEL_CHECKS: Record<string, CheckKey> = {
  wazuh_indexer: 'indexer',
  wazuh_dashboard: 'dashboard',
  wazuh_manager: 'manager',
  misp: 'misp',
  cortex: 'cortex',
  docker_engine: 'docker',
}

export function toServiceRecord(service: ApiHealthService): ServiceRecord {
  const panelKey = PANEL_CHECKS[service.check_key]
  const status = SERVICE_STATUS[service.status] ?? 'Unverified'

  return {
    id: service.check_key,
    name: service.name,
    category: service.category,
    group: panelKey ? 'vm' : 'pipeline',
    check: panelKey
      ? {
          key: panelKey,
          detail: service.detail ?? (service.status === 'unconfigured' ? 'Not configured on the backend' : status),
          uptimeSeconds: service.uptime_seconds,
          statusLabel: service.status === 'unconfigured' ? 'Not configured' : '',
        }
      : undefined,
    status,
    uptime:
      service.uptime_percent !== null && service.uptime_percent !== undefined
        ? `${service.uptime_percent.toFixed(2)}%`
        : 'Not measured',
    latency: service.latency_ms,
    version: 'Not reported',
    endpoint: service.endpoint ?? 'Not configured',
    lastCheck: secondsAgo(service.checked_at),
    description: service.detail ?? `${service.group} · ${service.category}`,
  }
}

function auditCategory(event: ApiAuditEvent): AuditCategory {
  const category = event.category.toLowerCase()

  if (category.includes('auth') || category.includes('session')) {
    return 'Authentication'
  }

  if (category.includes('policy')) {
    return 'Response Policy'
  }

  if (category.includes('user')) {
    return 'User Management'
  }

  if (event.source === 'incident' || category.includes('incident') || category.includes('response') || category.includes('approval')) {
    return 'Incident Response'
  }

  return 'System'
}

function auditResult(result: string): AuditResult {
  const value = result.toLowerCase()

  return value.startsWith('fail') ? 'Failed' : value.startsWith('den') || value.startsWith('block') ? 'Denied' : 'Success'
}

export function toAuditRecord(event: ApiAuditEvent): AuditLogRecord {
  const role = event.actor_role.toLowerCase().includes('admin')
    ? 'Administrator'
    : event.actor_role.toLowerCase().includes('analyst') || event.actor_role.toLowerCase().includes('soc')
      ? 'Analyst'
      : 'System'

  return {
    id: event.event_id,
    timestamp: auditTimestamp(event.occurred_at),
    user: event.actor_id,
    role,
    category: auditCategory(event),
    action: titleCase(event.action),
    target: event.target,
    result: auditResult(event.result),
    sourceIp: event.source_ip ?? 'Not recorded',
    description: event.message ?? `${titleCase(event.action)} on ${event.target}.`,
    changes: [],
    metadata: Object.fromEntries(
      [
        ['Event ID', event.event_id],
        ['Source', event.source === 'incident' ? 'Agent pipeline' : 'Operator'],
        ['Event type', event.event_type ?? ''],
        ['Record hash', event.row_hash ?? ''],
      ].filter(([, value]) => value),
    ),
  }
}

// ----- The action policy: backend snake_case <-> the Permissions page's ResponsePolicy -----

export function toResponsePolicy(doc: ApiActionPolicyDocument): ResponsePolicy {
  return {
    version: doc.version,
    whitelist: doc.whitelist.map((entry) => ({
      action: entry.action,
      mode: entry.mode === 'approval' ? 'Needs approval' : 'Automatic',
      ...(entry.limits
        ? {
            limits: {
              ...(entry.limits.default_minutes != null ? { defaultMinutes: entry.limits.default_minutes } : {}),
              ...(entry.limits.max_minutes != null ? { maxMinutes: entry.limits.max_minutes } : {}),
              approver: entry.limits.approver,
              windowMinutes: entry.limits.window_minutes,
              minRisk: entry.limits.min_risk,
            },
          }
        : {}),
    })),
    blacklist: doc.blacklist.map((entry) => ({ ...entry })),
    neverBlock: doc.never_block.map((target) => ({ ...target })),
    neverIsolate: doc.never_isolate.map((target) => ({ ...target })),
  }
}

export function fromResponsePolicy(policy: ResponsePolicy): ApiActionPolicyContent {
  return {
    whitelist: policy.whitelist.map((entry) => ({
      action: entry.action,
      mode: entry.mode === 'Needs approval' ? 'approval' : 'automatic',
      limits: entry.limits
        ? {
            default_minutes: entry.limits.defaultMinutes ?? null,
            max_minutes: entry.limits.maxMinutes ?? null,
            approver: entry.limits.approver,
            window_minutes: entry.limits.windowMinutes,
            min_risk: entry.limits.minRisk,
          }
        : null,
    })),
    blacklist: policy.blacklist.map(({ action, required }) => ({ action, required })),
    never_block: policy.neverBlock.map(({ value, label, required }) => ({ value, label, required })),
    never_isolate: policy.neverIsolate.map(({ value, label, required }) => ({ value, label, required })),
  }
}

// ----- Executed responses (GET /responses) -> the Incident Response page's runs -----

const RUN_ACTIONS: Record<string, ActionType> = {
  block_ip: 'Block IP',
  isolate_host: 'Isolate Host',
  lock_account: 'Lock Account',
  capture_telemetry: 'Capture Telemetry',
}

// "14:32" in the viewer's time zone: the page reads run times as clock times
function clock(iso: string) {
  const date = new Date(iso)

  return Number.isNaN(date.getTime()) ? iso : `${pad(date.getHours())}:${pad(date.getMinutes())}`
}

// "2026-08-03T16:16:10" in the viewer's time zone, the form the page's timeline reads
function localIso(iso: string) {
  const date = new Date(iso)

  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

export function toExecutionRecord(run: ApiResponseRun): ExecutionRecord {
  const failed =
    run.status === 'failed' || run.status === 'blocked' ||
    run.result?.status === 'failed' || run.verification?.status === 'FAILED'
  const finished = run.result?.at ?? null
  const timeline: TimelineItem[] = []

  if (run.approved_at) {
    timeline.push({ time: clock(run.approved_at), event: `Approved by ${run.approver_name ?? run.approved_by ?? 'an approver'}` })
  }
  timeline.push({ time: clock(run.created_at), event: `Sent to ${run.executor === 'cortex' ? 'Cortex' : run.executor}` })
  if (run.result) {
    timeline.push({ time: clock(run.result.at), event: run.result.message || `Result: ${run.result.status}` })
  }
  if (run.verification) {
    timeline.push({ time: clock(run.verification.at), event: `Verification ${run.verification.status.toLowerCase()}: ${run.verification.message}` })
  }
  // A completed rollback shows as the page's own "lifted automatically" step (reversedAt)
  if (run.rollback && run.rollback.status !== 'completed') {
    timeline.push({ time: clock(run.rollback.at), event: `Rollback failed: ${run.rollback.message}` })
  }

  return {
    id: run.response_action_id,
    triggeringAlert: run.alert_id ?? 'Not linked',
    approvalId: run.approval_id ?? '',
    policy: run.policy_decision_id ?? 'Not recorded',
    action: RUN_ACTIONS[run.action_type ?? ''] ?? 'Block IP',
    target: run.target ?? 'Not recorded',
    startTime: clock(run.created_at),
    endTime: finished ? clock(finished) : clock(run.created_at),
    duration: run.duration_minutes ? `${run.duration_minutes} min` : 'Not time-limited',
    result: failed ? 'Failed' : 'Completed',
    rollbackStatus: run.rollback
      ? run.rollback.status === 'completed'
        ? `Reversed ${friendlyTime(run.rollback.at)}`
        : `Rollback failed: ${run.rollback.message}`
      : run.expires_at
        ? `Reverses automatically ${friendlyTime(run.expires_at)}`
        : 'Does not reverse on its own',
    failureReason: failed
      ? run.result?.message || run.verification?.message || `The action ended as ${run.status}.`
      : '',
    happened: run.alert_id ? `Alert ${run.alert_id} on incident ${run.incident_id}.` : `Incident ${run.incident_id}.`,
    classified: '',
    responseReason: run.reason ?? '',
    evidence: [run.result?.message, run.verification?.message].filter((item): item is string => Boolean(item)),
    timeline,
    reversedAt: run.rollback?.status === 'completed' ? localIso(run.rollback.at) : undefined,
    approvedRole: run.approver_role ?? undefined,
    approvedByName: run.approver_name ?? run.approved_by ?? undefined,
  }
}
