import { baseURL } from './client';
import { getToken, getRefreshToken, setToken, clearToken, clearRefreshToken } from '../lib/auth';
import { refresh as refreshApi } from './auth';
import { api } from './client';

export const DELETE_CONFIRMATION_PHRASE = 'DELETE_MY_ACCOUNT';

export type ExportPreview = {
  counts: {
    categories: number;
    expenses: number;
    recurring_expenses: number;
    bills: number;
    reminders: number;
    subscriptions: number;
  };
};

export type AuditLogItem = {
  id: number;
  action: string;
  ip_address?: string | null;
  user_agent?: string | null;
  details?: Record<string, unknown> | null;
  created_at: string;
};

export async function exportPreview(): Promise<ExportPreview> {
  return api<ExportPreview>('/gdpr/export/preview');
}

export async function listAuditLog(limit = 20): Promise<{ items: AuditLogItem[] }> {
  return api<{ items: AuditLogItem[] }>(`/gdpr/audit-log?limit=${limit}`);
}

export async function deleteAccount(payload: {
  password: string;
  confirm: string;
}): Promise<{ message: string; deleted: Record<string, number> }> {
  return api('/gdpr/delete-account', { method: 'POST', body: payload });
}

async function authorizedFetch(path: string): Promise<Response> {
  async function doFetch(): Promise<Response> {
    const token = getToken();
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    return fetch(`${baseURL}${path}`, {
      method: 'GET',
      headers,
      credentials: 'include',
    });
  }

  let res = await doFetch();
  if (res.status === 401) {
    const rt = getRefreshToken();
    if (rt) {
      try {
        const r = await refreshApi(rt);
        setToken(r.access_token);
        res = await doFetch();
      } catch {
        clearToken();
        clearRefreshToken();
        throw new Error('Unauthorized');
      }
    } else {
      clearToken();
      clearRefreshToken();
      throw new Error('Unauthorized');
    }
  }
  return res;
}

/** Download the GDPR export ZIP and trigger a browser save. */
export async function downloadExportPackage(): Promise<void> {
  const res = await authorizedFetch('/gdpr/export?format=zip');
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: string };
      msg = body.error || msg;
    } catch {
      // ignore
    }
    throw new Error(msg);
  }
  const blob = await res.blob();
  const disposition = res.headers.get('Content-Disposition') || '';
  const match = /filename="?([^"]+)"?/i.exec(disposition);
  const filename = match?.[1] || `finmind-export-${new Date().toISOString().slice(0, 10)}.zip`;

  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
