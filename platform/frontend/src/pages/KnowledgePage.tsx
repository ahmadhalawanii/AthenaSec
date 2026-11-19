import { useEffect, useState, type FormEvent } from 'react'

import { ApiError } from '../api/client'
import {
  addKnowledgeDocument,
  approveKnowledgeDocument,
  getKnowledgeSource,
  importKnowledgeSeed,
  listKnowledgeDocuments,
  revokeKnowledgeDocument,
  type KnowledgeDocument,
  type KnowledgeStatus,
} from '../api/chatApi'
import TableScroll from '../components/TableScroll'

import '../styles/copilot.css'

// Text plus a tone, so the status never depends on colour alone
const STATUS_TONE: Record<KnowledgeStatus, string> = {
  approved: 'ok',
  draft: 'neutral',
  quarantined: 'danger',
  revoked: 'warn',
  superseded: 'neutral',
}

const ROLE_CHOICES = ['Analyst', 'Administrator'] as const

function when(iso: string | null) {
  return iso ? new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '-'
}

function problem(error: unknown) {
  return error instanceof ApiError ? error.message : 'Something went wrong. Please try again.'
}

type KnowledgePageProps = {
  // False in demo mode: there is no backend to talk to
  live: boolean
}

/*
  Administrators decide which documents the Security Copilot may quote. A document is a draft
  until approved; text that tries to instruct the assistant is quarantined and cannot be approved.
*/
function KnowledgePage({ live }: KnowledgePageProps) {
  const [documents, setDocuments] = useState<KnowledgeDocument[] | null>(null)
  const [message, setMessage] = useState('')
  const [failed, setFailed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [shown, setShown] = useState<{ id: string; text: string } | null>(null)

  const [slug, setSlug] = useState('')
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [roles, setRoles] = useState<string[]>([...ROLE_CHOICES])

  // Used after a change; the first load is in the effect below
  async function reload() {
    try {
      setDocuments((await listKnowledgeDocuments()).items)
      setFailed(false)
    } catch (error) {
      setFailed(true)
      setMessage(problem(error))
    }
  }

  useEffect(() => {
    if (!live) {
      return undefined
    }

    let cancelled = false

    listKnowledgeDocuments()
      .then((result) => {
        if (!cancelled) {
          setDocuments(result.items)
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setFailed(true)
          setMessage(problem(error))
        }
      })

    return () => {
      cancelled = true
    }
  }, [live])

  async function act(work: () => Promise<string>) {
    setBusy(true)
    setFailed(false)

    try {
      setMessage(await work())
      await reload()
    } catch (error) {
      setFailed(true)
      setMessage(problem(error))
    } finally {
      setBusy(false)
    }
  }

  function add(event: FormEvent) {
    event.preventDefault()
    void act(async () => {
      const doc = await addKnowledgeDocument({ slug, title, body, allowed_roles: roles })
      setBody('')

      return doc.status === 'quarantined'
        ? `"${doc.title}" was quarantined because it ${doc.quarantine_reason}. It cannot be approved; remove that text and add it again.`
        : `"${doc.title}" was added as a draft (version ${doc.version}). Review it, then approve it.`
    })
  }

  async function view(doc: KnowledgeDocument) {
    if (shown?.id === doc.doc_id) {
      setShown(null)
      return
    }

    try {
      const source = await getKnowledgeSource(doc.doc_id)
      setShown({ id: doc.doc_id, text: source.text })
    } catch (error) {
      setFailed(true)
      setMessage(problem(error))
    }
  }

  return (
    <section className="page active" data-page="knowledge" data-page-name="Knowledge base">
      <div className="headline">
        <div>
          <h1>Knowledge base</h1>
          <p className="sub">
            Documents the Security Copilot may quote. Only approved documents are used, and each one
            lists who may read it.
          </p>
        </div>

        <div className="headline-actions">
          <button
            type="button"
            className="btn"
            disabled={!live || busy}
            onClick={() =>
              void act(async () => {
                const { created } = await importKnowledgeSeed()

                return created.length
                  ? `${created.length} starter documents were added as drafts. Review each one, then approve it.`
                  : 'The starter documents are already there.'
              })
            }
          >
            Import starter documents
          </button>
        </div>
      </div>

      {!live && (
        <p className="copilot-note" role="status">
          The knowledge base needs the live AthenaSec backend. This is demo data, so it is turned off.
        </p>
      )}

      {message && (
        <p className="copilot-note" role={failed ? 'alert' : 'status'}>
          {message}
        </p>
      )}

      <div className="card">
        <h2>Documents</h2>

        {documents && documents.length === 0 && (
          <p className="sub">No documents yet. Import the starter documents or add one below.</p>
        )}

        {documents && documents.length > 0 && (
          <TableScroll label="Knowledge documents">
            <table>
              <thead>
                <tr>
                  <th scope="col">Document</th>
                  <th scope="col">Version</th>
                  <th scope="col">Status</th>
                  <th scope="col">Readable by</th>
                  <th scope="col">Approved</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {documents.map((doc) => (
                  <tr key={doc.doc_id}>
                    <td>
                      <strong>{doc.title}</strong>
                      <br />
                      <code>{doc.doc_id}</code>
                    </td>
                    <td>{doc.version}</td>
                    <td>
                      <span className={`pill ${STATUS_TONE[doc.status]}`}>{doc.status}</span>
                      {doc.quarantine_reason && (
                        <div className="copilot-meta">Reason: {doc.quarantine_reason}</div>
                      )}
                    </td>
                    <td>{doc.allowed_roles.join(', ')}</td>
                    <td>
                      {doc.approved_by ? `${doc.approved_by}, ${when(doc.approved_at)}` : '-'}
                    </td>
                    <td className="copilot-chips">
                      <button type="button" className="btn small" onClick={() => void view(doc)}>
                        {shown?.id === doc.doc_id ? 'Hide' : 'View'}
                      </button>
                      {doc.status === 'draft' && (
                        <button
                          type="button"
                          className="btn small primary"
                          disabled={busy}
                          onClick={() =>
                            void act(async () => {
                              await approveKnowledgeDocument(doc.doc_id)
                              return `"${doc.title}" is approved. The Copilot may now quote it.`
                            })
                          }
                        >
                          Approve
                        </button>
                      )}
                      {doc.status !== 'revoked' && (
                        <button
                          type="button"
                          className="btn small"
                          disabled={busy}
                          onClick={() => {
                            if (window.confirm(`Revoke "${doc.title}"? The Copilot stops quoting it at once.`)) {
                              void act(async () => {
                                await revokeKnowledgeDocument(doc.doc_id)
                                return `"${doc.title}" was revoked.`
                              })
                            }
                          }}
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        )}

        {shown && (
          <pre className="copilot-doc" aria-label="Document text">
            {shown.text}
          </pre>
        )}
      </div>

      <div className="card">
        <h2>Add a document</h2>
        <form className="copilot-add" onSubmit={add}>
          <label>
            Short name (letters, digits and hyphens)
            <input
              className="field-input"
              value={slug}
              maxLength={64}
              onChange={(event) => setSlug(event.target.value.toLowerCase())}
              placeholder="brute-force-response"
              required
            />
          </label>
          <label>
            Title
            <input
              className="field-input"
              value={title}
              maxLength={200}
              onChange={(event) => setTitle(event.target.value)}
              required
            />
          </label>
          <fieldset>
            <legend>Readable by</legend>
            {ROLE_CHOICES.map((role) => (
              <label key={role} className="copilot-check">
                <input
                  type="checkbox"
                  checked={roles.includes(role)}
                  onChange={(event) =>
                    setRoles((current) =>
                      event.target.checked ? [...current, role] : current.filter((r) => r !== role),
                    )
                  }
                />
                {role}
              </label>
            ))}
          </fieldset>
          <label>
            Text (Markdown; each # heading starts a new section)
            <textarea
              className="field-input"
              rows={10}
              value={body}
              onChange={(event) => setBody(event.target.value)}
              required
            />
          </label>
          <button type="submit" className="btn primary" disabled={!live || busy || roles.length === 0}>
            Add as draft
          </button>
        </form>
      </div>
    </section>
  )
}

export default KnowledgePage
