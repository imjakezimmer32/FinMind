import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { me, updateMe } from '@/api/auth';
import {
  confirmAccountDeletion,
  exportPrivacyData,
  listPrivacyAudit,
  requestAccountDeletion,
  type PrivacyAuditEvent,
} from '@/api/privacy';
import { clearRefreshToken, clearToken, setCurrency } from '@/lib/auth';

const SUPPORTED_CURRENCIES = [
  { code: 'INR', label: 'Indian Rupee (INR)' },
  { code: 'USD', label: 'US Dollar (USD)' },
  { code: 'EUR', label: 'Euro (EUR)' },
  { code: 'GBP', label: 'British Pound (GBP)' },
  { code: 'AED', label: 'UAE Dirham (AED)' },
  { code: 'SGD', label: 'Singapore Dollar (SGD)' },
  { code: 'AUD', label: 'Australian Dollar (AUD)' },
  { code: 'CAD', label: 'Canadian Dollar (CAD)' },
  { code: 'JPY', label: 'Japanese Yen (JPY)' },
];

const DELETE_CONFIRMATION = 'DELETE_MY_DATA';

export default function Account() {
  const { toast } = useToast();
  const [email, setEmail] = useState('');
  const [currency, setCurrencyState] = useState('INR');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [requestingDelete, setRequestingDelete] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [password, setPassword] = useState('');
  const [confirmationToken, setConfirmationToken] = useState('');
  const [confirmPhrase, setConfirmPhrase] = useState('');
  const [auditEvents, setAuditEvents] = useState<PrivacyAuditEvent[]>([]);

  const loadAudit = async () => {
    try {
      const events = await listPrivacyAudit();
      setAuditEvents(events);
    } catch {
      // Audit trail is optional for page load; keep settings usable.
    }
  };

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const data = await me();
        setEmail(data.email);
        setCurrencyState(data.preferred_currency || 'INR');
        await loadAudit();
      } catch (error: unknown) {
        const message =
          error instanceof Error ? error.message : 'Failed to load account';
        toast({ title: 'Failed to load account', description: message });
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, [toast]);

  const onSave = async () => {
    setSaving(true);
    try {
      const updated = await updateMe({ preferred_currency: currency });
      setCurrency(updated.preferred_currency);
      toast({
        title: 'Account updated',
        description: `Default currency set to ${updated.preferred_currency}.`,
      });
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Failed to update account';
      toast({ title: 'Failed to update account', description: message });
    } finally {
      setSaving(false);
    }
  };

  const onExport = async () => {
    setExporting(true);
    try {
      const blob = await exportPrivacyData();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      anchor.href = url;
      anchor.download = `finmind-data-export-${stamp}.zip`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      toast({
        title: 'Export ready',
        description: 'Your personal data package was downloaded.',
      });
      await loadAudit();
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Failed to export data';
      toast({ title: 'Export failed', description: message });
    } finally {
      setExporting(false);
    }
  };

  const onRequestDelete = async () => {
    if (!password) {
      toast({
        title: 'Password required',
        description: 'Enter your password to start account deletion.',
      });
      return;
    }
    setRequestingDelete(true);
    try {
      const result = await requestAccountDeletion(password);
      setConfirmationToken(result.confirmation_token);
      toast({
        title: 'Confirm deletion',
        description: `Type ${result.confirm_phrase} below within ${Math.round(
          result.expires_in_seconds / 60,
        )} minutes to permanently delete your account.`,
      });
      await loadAudit();
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Failed to start deletion';
      toast({ title: 'Delete request failed', description: message });
    } finally {
      setRequestingDelete(false);
    }
  };

  const onConfirmDelete = async () => {
    if (!confirmationToken) {
      toast({
        title: 'Start deletion first',
        description: 'Request deletion with your password before confirming.',
      });
      return;
    }
    if (confirmPhrase !== DELETE_CONFIRMATION) {
      toast({
        title: 'Confirmation phrase required',
        description: `Type ${DELETE_CONFIRMATION} exactly to continue.`,
      });
      return;
    }
    setConfirmingDelete(true);
    try {
      await confirmAccountDeletion({
        confirmation_token: confirmationToken,
        confirm: DELETE_CONFIRMATION,
      });
      clearToken();
      clearRefreshToken();
      toast({
        title: 'Account deleted',
        description: 'Your FinMind account and personal data were deleted.',
      });
      window.location.assign('/');
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Failed to delete account';
      toast({ title: 'Delete failed', description: message });
      setConfirmingDelete(false);
    }
  };

  return (
    <div className="page-wrap space-y-6">
      <div className="page-header">
        <div className="relative">
          <h1 className="page-title">Account Settings</h1>
          <p className="page-subtitle">
            Manage your profile defaults. Currency stays fixed until you change
            it again.
          </p>
        </div>
      </div>

      <div className="card card-interactive space-y-5 fade-in-up">
        {loading ? (
          <div className="text-sm text-muted-foreground">Loading account...</div>
        ) : (
          <>
            <div className="space-y-2">
              <Label>Email</Label>
              <div className="input bg-muted/30">{email}</div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="preferred_currency">Preferred Currency</Label>
              <select
                id="preferred_currency"
                className="input"
                value={currency}
                onChange={(e) => setCurrencyState(e.target.value)}
              >
                {SUPPORTED_CURRENCIES.map((item) => (
                  <option key={item.code} value={item.code}>
                    {item.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex justify-end">
              <Button
                variant="financial"
                onClick={onSave}
                disabled={saving || loading}
              >
                {saving ? 'Saving...' : 'Save Preferences'}
              </Button>
            </div>
          </>
        )}
      </div>

      <div className="card card-interactive space-y-5 fade-in-up">
        <div>
          <h2 className="text-lg font-semibold">Privacy Controls</h2>
          <p className="text-sm text-muted-foreground">
            Export your personal data package or permanently delete your
            account. Deletion is irreversible.
          </p>
        </div>

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <Label>Personal data export</Label>
            <p className="text-sm text-muted-foreground">
              Download a ZIP with JSON and CSV copies of your FinMind data.
            </p>
          </div>
          <Button
            variant="outline"
            onClick={onExport}
            disabled={exporting || loading}
          >
            {exporting ? 'Exporting...' : 'Download Export'}
          </Button>
        </div>

        <div className="space-y-3 border-t border-border pt-4">
          <div>
            <Label htmlFor="delete_password">Delete account</Label>
            <p className="text-sm text-muted-foreground">
              Step 1: re-enter your password. Step 2: type {DELETE_CONFIRMATION}{' '}
              to permanently erase your data.
            </p>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row">
            <input
              id="delete_password"
              type="password"
              className="input"
              placeholder="Account password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={requestingDelete || confirmingDelete || loading}
            />
            <Button
              variant="outline"
              onClick={onRequestDelete}
              disabled={requestingDelete || confirmingDelete || loading}
            >
              {requestingDelete ? 'Requesting...' : 'Request Deletion'}
            </Button>
          </div>
          {confirmationToken ? (
            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                id="delete_confirmation"
                className="input"
                placeholder={DELETE_CONFIRMATION}
                value={confirmPhrase}
                onChange={(event) => setConfirmPhrase(event.target.value)}
                disabled={confirmingDelete || loading}
              />
              <Button
                variant="destructive"
                onClick={onConfirmDelete}
                disabled={confirmingDelete || loading}
              >
                {confirmingDelete ? 'Deleting...' : 'Confirm Permanent Delete'}
              </Button>
            </div>
          ) : null}
        </div>

        {auditEvents.length > 0 ? (
          <div className="space-y-2 border-t border-border pt-4">
            <Label>Privacy audit trail</Label>
            <ul className="space-y-2 text-sm text-muted-foreground">
              {auditEvents.slice(0, 5).map((event) => (
                <li key={event.id}>
                  {event.action} · {new Date(event.created_at).toLocaleString()}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </div>
  );
}
