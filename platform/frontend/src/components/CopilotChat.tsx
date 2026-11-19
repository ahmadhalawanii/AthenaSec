import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import { Link } from 'react-router-dom'

import { ApiError } from '../api/client'
import {
  createChatSession,
  getKnowledgeSource,
  sendChatFeedback,
  sendChatMessage,
  type ChatAnswer,
  type FeedbackCategory,
  type Presentation,
} from '../api/chatApi'

import '../styles/copilot.css'

const STARTERS = [
  'Are there any urgent problems?',
  'Show my unresolved cases',
  'What has AthenaSec done today?',
  'What is waiting for approval?',
  'Is monitoring working?',
  'Is autonomous response enabled?',
  'What does brute force mean?',
]

const MAX_LENGTH = 2000

type Turn =
  | { id: number; role: 'user'; text: string }
  | { id: number; role: 'assistant'; reply: ChatAnswer }
  | { id: number; role: 'error'; text: string }

// Text plus the data source, so status never depends on colour alone
const STATUS_TEXT: Record<ChatAnswer['data_status'], string> = {
  live: 'Live',
  stored: 'From stored records',
  cached: 'Cached',
  partial: 'Partial results',
  unavailable: 'Unable to confirm',
}

function checkedTime(iso: string) {
  const when = new Date(iso)

  return Number.isNaN(when.getTime())
    ? iso
    : when.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

// A quoted document or glossary entry, opened on demand so the reader can check it
function KnowledgeSource({ sourceId }: { sourceId: string }) {
  const [text, setText] = useState<string | null>(null)
  const [error, setError] = useState(false)

  async function load(open: boolean) {
    if (!open || text !== null) {
      return
    }

    try {
      const source = await getKnowledgeSource(sourceId)
      setText(`${source.title}${source.version ? ` (version ${source.version})` : ''}\n\n${source.text}`)
    } catch {
      setError(true)
    }
  }

  return (
    <details className="copilot-tech" onToggle={(event) => void load(event.currentTarget.open)}>
      <summary>View source: {sourceId}</summary>
      {error ? <p role="alert">This source could not be opened.</p> : <pre>{text ?? 'Loading…'}</pre>}
    </details>
  )
}

const FEEDBACK_CHOICES: [FeedbackCategory, string][] = [
  ['confusing', 'This was confusing'],
  ['wrong_source', 'The source looks wrong'],
  ['incorrect', 'This is incorrect'],
  ['other', 'Something else'],
]

// Tells the team an answer was unclear or wrong. It never edits the answer or any record.
function Feedback({ messageId }: { messageId: string }) {
  const [category, setCategory] = useState<FeedbackCategory>('confusing')
  const [note, setNote] = useState('')
  const [state, setState] = useState<'idle' | 'sending' | 'sent' | 'failed'>('idle')

  async function send(event: FormEvent) {
    event.preventDefault()
    setState('sending')

    try {
      await sendChatFeedback(messageId, category, note)
      setState('sent')
    } catch {
      setState('failed')
    }
  }

  if (state === 'sent') {
    return (
      <p className="copilot-meta" role="status">
        Thanks, your feedback was recorded. It does not change any security record.
      </p>
    )
  }

  return (
    <details className="copilot-feedback">
      <summary>Report a problem with this answer</summary>
      <form onSubmit={send}>
        <label>
          What was wrong?
          <select
            className="field-input"
            value={category}
            onChange={(event) => setCategory(event.target.value as FeedbackCategory)}
          >
            {FEEDBACK_CHOICES.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Details (optional)
          <input
            className="field-input"
            maxLength={500}
            value={note}
            onChange={(event) => setNote(event.target.value)}
          />
        </label>
        <button type="submit" className="btn small" disabled={state === 'sending'}>
          Send feedback
        </button>
        {state === 'failed' && (
          <p className="copilot-meta" role="alert">
            The feedback could not be sent. Try again.
          </p>
        )}
      </form>
    </details>
  )
}

type CopilotChatProps = {
  role: 'Analyst' | 'Administrator'
  // False in demo mode: there is no backend to ask
  live: boolean
  // The popup: a tighter layout, and the message box is focused when it opens
  compact?: boolean
  // Bump to move focus into the message box (the popup does this each time it opens)
  focusSignal?: number
}

/*
  The conversation itself, used by the Security Copilot page and by the popup on every page.
  It reads stored records only; the backend never lets the chat act.
*/
function CopilotChat({ role, live, compact = false, focusSignal = 0 }: CopilotChatProps) {
  const [turns, setTurns] = useState<Turn[]>([])
  const [draft, setDraft] = useState('')
  const [presentation, setPresentation] = useState<Presentation>('simple')
  const [pending, setPending] = useState(false)
  const sessionId = useRef<string | null>(null)
  const nextId = useRef(1)
  const bottom = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    bottom.current?.scrollIntoView?.({ block: 'end' })
  }, [turns, pending])

  useEffect(() => {
    if (focusSignal > 0) {
      input.current?.focus()
    }
  }, [focusSignal])

  async function ask(text: string) {
    const content = text.trim()

    if (!content || pending) {
      return
    }

    setTurns((current) => [...current, { id: nextId.current++, role: 'user', text: content }])
    setDraft('')
    setPending(true)

    try {
      if (!sessionId.current) {
        sessionId.current = (await createChatSession(presentation)).session_id
      }

      const reply = await sendChatMessage(sessionId.current, content, presentation)

      setTurns((current) => [...current, { id: nextId.current++, role: 'assistant', reply }])
    } catch (error) {
      const text =
        error instanceof ApiError && error.unreachable
          ? 'I could not reach AthenaSec, so I cannot confirm anything right now. Try again shortly.'
          : error instanceof ApiError
            ? error.message
            : 'Something went wrong. Please try again.'

      setTurns((current) => [...current, { id: nextId.current++, role: 'error', text }])
    } finally {
      setPending(false)
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    void ask(draft)
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    // Enter sends; Shift+Enter adds a line
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault()
      void ask(draft)
    }
  }

  function newConversation() {
    sessionId.current = null
    setTurns([])
  }

  return (
    <div className={compact ? 'copilot copilot-compact' : 'copilot'}>
      <div className="copilot-bar">
        <div className="copilot-view" role="group" aria-label="Answer style">
          {(['simple', 'technical'] as const).map((choice) => (
            <button
              key={choice}
              type="button"
              className={presentation === choice ? 'btn small primary' : 'btn small'}
              aria-pressed={presentation === choice}
              onClick={() => setPresentation(choice)}
            >
              {choice === 'simple' ? 'Simple' : 'Technical'}
            </button>
          ))}
        </div>

        <button
          type="button"
          className="btn small"
          onClick={newConversation}
          disabled={pending || turns.length === 0}
        >
          New conversation
        </button>
      </div>

      {!live && (
        <p className="copilot-note" role="status">
          The Copilot needs the live AthenaSec backend. This is demo data, so it is turned off.
        </p>
      )}

      <div className="copilot-log" role="log" aria-live="polite" aria-label="Conversation">
        {turns.length === 0 && (
          <div className="copilot-empty">
            <p>Choose a question, or type your own.</p>
            <div className="copilot-chips">
              {STARTERS.map((starter) => (
                <button
                  key={starter}
                  type="button"
                  className="btn small"
                  disabled={!live || pending}
                  onClick={() => void ask(starter)}
                >
                  {starter}
                </button>
              ))}
            </div>
          </div>
        )}

        {turns.map((turn) => {
          if (turn.role === 'user') {
            return (
              <div key={turn.id} className="copilot-turn copilot-user">
                <span className="copilot-who">You</span>
                <p>{turn.text}</p>
              </div>
            )
          }

          if (turn.role === 'error') {
            return (
              <div key={turn.id} className="copilot-turn copilot-error" role="alert">
                <span className="copilot-who">Problem</span>
                <p>{turn.text}</p>
              </div>
            )
          }

          const { reply } = turn
          const has = (type: string) => reply.evidence_refs.some((ref) => ref.type === type)
          const isAnalyst = role === 'Analyst'
          const isAdmin = role === 'Administrator'

          return (
            <div key={turn.id} className="copilot-turn copilot-bot">
              <span className="copilot-who">Security Copilot</span>
              <p>{reply.answer}</p>

              {reply.known_limitations.length > 0 && (
                <ul className="copilot-limits">
                  {reply.known_limitations.map((limit) => (
                    <li key={limit}>{limit}</li>
                  ))}
                </ul>
              )}

              {reply.evidence_refs.some((ref) => ref.type !== 'knowledge') && (
                <p className="copilot-sources">
                  <strong>Sources:</strong>{' '}
                  {reply.evidence_refs
                    .filter((ref) => ref.type !== 'audit' && ref.type !== 'knowledge')
                    .map((ref) => (
                      <span key={`${ref.type}-${ref.id}`}>
                        <code>{ref.id}</code>{' '}
                      </span>
                    ))}
                  {/* Audit event IDs are long hashes; a count reads better and the page has them */}
                  {has('audit') && (
                    <span>
                      {reply.evidence_refs.filter((ref) => ref.type === 'audit').length} audit events{' '}
                    </span>
                  )}
                  {/* Only link to pages this role can open */}
                  {isAnalyst && has('alert') && <Link to="/app/alerts">Open Alerts</Link>}
                  {isAnalyst && has('case') && <Link to="/app/cases">Open Case Management</Link>}
                  {has('approval') && <Link to="/app/approvals">Open Approvals</Link>}
                  {isAdmin && has('audit') && <Link to="/app/audit-logs">Open Audit Logs</Link>}
                  {isAdmin && has('system') && <Link to="/app/service-panel">Open Service Panel</Link>}
                </p>
              )}

              {reply.evidence_refs
                .filter((ref) => ref.type === 'knowledge')
                .map((ref) => (
                  <KnowledgeSource key={ref.id} sourceId={ref.id} />
                ))}

              <p className="copilot-meta">
                <span className={`pill ${reply.data_status === 'unavailable' ? 'warn' : 'neutral'}`}>
                  {STATUS_TEXT[reply.data_status]}
                </span>{' '}
                Checked {checkedTime(reply.checked_at)}
              </p>

              {reply.technical && (
                <details className="copilot-tech">
                  <summary>Technical details</summary>
                  <pre>{JSON.stringify(reply.technical, null, 2)}</pre>
                </details>
              )}

              <Feedback messageId={reply.message_id} />

              {reply.suggested_followups.length > 0 && (
                <div className="copilot-chips">
                  {reply.suggested_followups.map((followup) => (
                    <button
                      key={followup}
                      type="button"
                      className="btn small ghost"
                      disabled={pending}
                      onClick={() => void ask(followup)}
                    >
                      {followup}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )
        })}

        {pending && (
          <p className="copilot-typing" role="status">
            Checking AthenaSec records…
          </p>
        )}

        <div ref={bottom} />
      </div>

      <form className="copilot-form" onSubmit={submit}>
        <label htmlFor={compact ? 'copilot-input-popup' : 'copilot-input'} className="visually-hidden">
          Ask the Security Copilot
        </label>
        <textarea
          id={compact ? 'copilot-input-popup' : 'copilot-input'}
          ref={input}
          className="field-input"
          rows={2}
          maxLength={MAX_LENGTH}
          value={draft}
          disabled={!live}
          placeholder="Ask about your security, an alert ID, or a case ID"
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={onKeyDown}
        />
        <button type="submit" className="btn primary" disabled={!live || pending || !draft.trim()}>
          Send
        </button>
      </form>
    </div>
  )
}

export default CopilotChat
