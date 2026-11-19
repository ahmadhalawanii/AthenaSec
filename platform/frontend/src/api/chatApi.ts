/* Security Copilot (backend/app/chat). Read-only: it explains stored records and cannot act. */
import { api } from './client'

export type Presentation = 'simple' | 'technical'

export type ChatEvidenceRef = {
  type: 'alert' | 'case' | 'approval' | 'audit' | 'system' | 'knowledge'
  id: string
  href: string
}

export type FeedbackCategory = 'confusing' | 'wrong_source' | 'incorrect' | 'other'

export type ChatAnswer = {
  message_id: string
  answer: string
  answer_type: 'knowledge' | 'operational' | 'investigation' | 'action_status' | 'unable_to_verify'
  data_status: 'live' | 'stored' | 'cached' | 'partial' | 'unavailable'
  checked_at: string
  evidence_refs: ChatEvidenceRef[]
  known_limitations: string[]
  suggested_followups: string[]
  technical: Record<string, unknown> | null
}

export function createChatSession(presentation: Presentation) {
  return api<{ session_id: string }>('/chat/sessions', {
    method: 'POST',
    body: { presentation },
  })
}

// Feedback is only recorded for review; it never changes an answer or a security record
export function sendChatFeedback(messageId: string, category: FeedbackCategory, note: string) {
  return api<{ feedback_id: string }>('/chat/feedback', {
    method: 'POST',
    body: { message_id: messageId, category, note: note.trim() || null },
  })
}

// Qwen may reword the answer, which can take longer than the usual request limit
export function sendChatMessage(sessionId: string, content: string, presentation: Presentation) {
  return api<ChatAnswer>(`/chat/sessions/${encodeURIComponent(sessionId)}/messages`, {
    method: 'POST',
    body: { content, presentation },
    timeoutMs: 60000,
  })
}

// ---- Knowledge base: documents the Copilot may quote ----

export type KnowledgeStatus = 'draft' | 'approved' | 'quarantined' | 'revoked' | 'superseded'

export type KnowledgeDocument = {
  doc_id: string
  slug: string
  version: number
  title: string
  status: KnowledgeStatus
  allowed_roles: string[]
  created_by: string
  created_at: string
  approved_by: string | null
  approved_at: string | null
  quarantine_reason: string | null
}

export type KnowledgeSource = {
  source_id: string
  title: string
  text: string
  version?: number
  status?: KnowledgeStatus
}

export function getKnowledgeSource(sourceId: string) {
  return api<KnowledgeSource>(`/chat/knowledge/sources/${encodeURIComponent(sourceId)}`)
}

const DOCS = '/chat/knowledge/documents'

export const listKnowledgeDocuments = () => api<{ items: KnowledgeDocument[] }>(DOCS)

export const addKnowledgeDocument = (body: {
  slug: string
  title: string
  body: string
  allowed_roles: string[]
}) => api<KnowledgeDocument>(DOCS, { method: 'POST', body })

export const approveKnowledgeDocument = (docId: string) =>
  api<KnowledgeDocument>(`${DOCS}/${encodeURIComponent(docId)}/approve`, { method: 'POST', body: {} })

export const revokeKnowledgeDocument = (docId: string) =>
  api<KnowledgeDocument>(`${DOCS}/${encodeURIComponent(docId)}/revoke`, { method: 'POST', body: {} })

export const importKnowledgeSeed = () =>
  api<{ created: KnowledgeDocument[] }>('/chat/knowledge/seed', { method: 'POST', body: {} })

// ---- History and feedback review ----

export type ChatSessionSummary = {
  session_id: string
  created_at: string
  presentation: Presentation
  preview: string
}

export type SavedMessage = {
  message_id: string
  role: 'user' | 'assistant'
  content: string
  created_at: string
  evidence_refs: ChatEvidenceRef[]
  data_status: ChatAnswer['data_status'] | null
  answer_type: ChatAnswer['answer_type'] | null
  checked_at: string | null
  known_limitations: string[]
  suggested_followups: string[]
}

export const listChatSessions = () => api<{ items: ChatSessionSummary[] }>('/chat/sessions')

export const getChatSession = (sessionId: string) =>
  api<{ session_id: string; presentation: Presentation; messages: SavedMessage[] }>(
    `/chat/sessions/${encodeURIComponent(sessionId)}`,
  )

export type ChatFeedbackItem = {
  feedback_id: string
  message_id: string
  owner_id: string
  category: FeedbackCategory
  note: string | null
  created_at: string
  answer: string
}

// Administrators only: what people reported, and the answer they reported (never the question)
export const listChatFeedback = () => api<{ items: ChatFeedbackItem[] }>('/chat/feedback')
