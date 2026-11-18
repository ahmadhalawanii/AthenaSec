import { useEffect, useState } from 'react'
import { api } from '../api/client'

type Section = 'overview' | 'evidence' | 'response'
type Investigation = Record<string, unknown>

function readable(value: unknown): string {
  if (value === null || value === undefined) return 'Not recorded'
  if (typeof value === 'string') return value || 'Not recorded'
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value, null, 2)
}

function Detail({ title, value }: { title: string; value: unknown }) {
  if (value === null || value === undefined) {
    return (
      <p className="workspace-text">
        <strong>{title}:</strong> Not recorded
      </p>
    )
  }

  return (
    <div style={{ marginBottom: 16 }}>
      <h4 className="workspace-subhead">{title}</h4>
      {typeof value === 'object' ? (
        <pre style={{
          whiteSpace: 'pre-wrap',
          overflowWrap: 'anywhere',
          fontSize: 13,
          lineHeight: 1.6,
          padding: 14,
          borderRadius: 10,
          background: 'rgba(127,127,127,0.08)',
          maxHeight: 480,
          overflowY: 'auto',
        }}>
          {readable(value)}
        </pre>
      ) : (
        <p className="workspace-text">{readable(value)}</p>
      )}
    </div>
  )
}

function LiveInvestigationDetails({
  alertId,
  section,
}: {
  alertId: string
  section: Section
}) {
  const [data, setData] = useState<Investigation | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const result = await api<Investigation>(
          `/investigations/${encodeURIComponent(alertId)}`
        )
        if (!cancelled) {
          setData(result)
          setError(null)
          setLoading(false)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Investigation unavailable')
          setLoading(false)
        }
      }
    }

    setData(null)
    setLoading(true)
    void load()

    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void load()
    }, 10000)

    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [alertId])

  if (loading) {
    return <p className="workspace-text">Loading live investigation...</p>
  }

  if (!data) {
    return (
      <p className="workspace-text">
        Investigation not available yet.
        {error ? ` ${error}` : ''}
      </p>
    )
  }

  if (section === 'evidence') {
    return (
      <div>
        <Detail title="Wazuh event" value={data.normalized_event} />
        <Detail title="Evidence records" value={data.evidence_records} />
        <Detail title="Evidence sufficiency" value={data.evidence_sufficiency} />
        <Detail title="MISP threat intelligence" value={data.misp_enrichment} />
        {data.misp_error != null && <Detail title="MISP error" value={data.misp_error} />}
        <Detail title="Analysis verification" value={data.analysis_verification} />
        <Detail title="Investigation trace" value={data.investigation_trace} />
      </div>
    )
  }

  if (section === 'response') {
    return (
      <div>
        <Detail title="AI response recommendation" value={data.response_proposal} />
        <Detail title="Proposed actions" value={data.proposed_actions} />
        <Detail title="Action risk assessments" value={data.action_risk_assessments} />
        <Detail title="Deterministic action policy" value={data.action_policy_decisions} />
        <Detail title="Approval requests" value={data.approval_requests} />
        <Detail title="Response plan" value={data.response_plan} />
        <Detail title="Recorded execution result" value={data.execution_result} />
        <p className="policy-note">
          A recommendation is not proof of execution. Cortex verification and
          rollback records, where available, are shown in Incident Response.
        </p>
      </div>
    )
  }

  return (
    <div>
      <h3 className="workspace-subhead">AI investigation</h3>
      <Detail title="Qwen analysis" value={data.analysis} />
      <Detail title="ML classification" value={data.ml_prediction} />
      {data.ml_error != null && <Detail title="ML error" value={data.ml_error} />}
      <Detail title="Incident risk assessment" value={data.risk_assessment} />
      <Detail title="Incident policy decision" value={data.policy_decision} />
      <Detail title="AI recommended response" value={data.response_proposal} />
      <Detail title="Deterministic action decisions" value={data.action_policy_decisions} />
      <Detail title="Actual execution result" value={data.execution_result} />
      {data.investigation_budget_exhausted === true && (
        <p className="workspace-text">
          Investigation budget exhausted; check the trace and escalation status.
        </p>
      )}
    </div>
  )
}

export default LiveInvestigationDetails
