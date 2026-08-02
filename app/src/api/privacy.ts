import { api, baseURL } from './client';
import { getToken } from '../lib/auth';

export type DeleteRequestResponse = {
  message: string;
  confirmation_token: string;
  expires_in_seconds: number;
  confirm_phrase: string;
};

export type DeleteConfirmResponse = {
  message: string;
  deleted_records: Record<string, number>;
  anonymized_audit_logs: number;
  deleted_cache_keys: number;
  revoked_refresh_sessions: number;
};

export type PrivacyAuditEvent = {
  id: number;
  action: string;
  ip_address?: string | null;
  user_agent?: string | null;
  details?: Record<string, unknown> | null;
  created_at: string;
};

export async function exportPrivacyData(): Promise<Blob> {
  const token = getToken();
  const res = await fetch(`${baseURL}/privacy/export`, {
    method: 'GET',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    credentials: 'include',
  });
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const payload = (await res.json()) as { error?: string; message?: string };
      message = payload.error || payload.message || message;
    } catch {
      // Keep status-based fallback for non-JSON failures.
    }
    throw new Error(message);
  }
  return res.blob();
}

export async function requestAccountDeletion(
  password: string,
): Promise<DeleteRequestResponse> {
  return api<DeleteRequestResponse>('/privacy/delete/request', {
    method: 'POST',
    body: { password },
  });
}

export async function confirmAccountDeletion(payload: {
  confirmation_token: string;
  confirm: string;
}): Promise<DeleteConfirmResponse> {
  return api<DeleteConfirmResponse>('/privacy/delete/confirm', {
    method: 'POST',
    body: payload,
  });
}

export async function listPrivacyAudit(): Promise<PrivacyAuditEvent[]> {
  return api<PrivacyAuditEvent[]>('/privacy/audit');
}
