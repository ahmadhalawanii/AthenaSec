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
