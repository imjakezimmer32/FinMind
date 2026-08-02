import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { me, updateMe } from '@/api/auth';
import {
  DELETE_CONFIRMATION_PHRASE,
  deleteAccount,
  downloadExportPackage,
  exportPreview,
  listAuditLog,
  type AuditLogItem,
  type ExportPreview,
} from '@/api/gdpr';
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

export default function Account() {
  const { toast } = useToast();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [currency, setCurrencyState] = useState('INR');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [preview, setPreview] = useState<ExportPreview['counts'] | null>(null);
  const [auditItems, setAuditItems] = useState<AuditLogItem[]>([]);
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteConfirm, setDeleteConfirm] = useState('');
  const [deleting, setDeleting] = useState(false);

  const loadPrivacy = async () => {
    try {
      const [previewRes, auditRes] = await Promise.all([
        exportPreview(),
        listAuditLog(10),
      ]);
      setPreview(previewRes.counts);
      setAuditItems(auditRes.items);
    } catch {
      // Privacy section is optional if API unavailable; Account still loads.
    }
  };

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const data = await me();
        setEmail(data.email);
        setCurrencyState(data.preferred_currency || 'INR');
        await loadPrivacy();
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
      await downloadExportPackage();
      toast({
        title: 'Export ready',
        description: 'Your personal data package was downloaded.',
      });
      await loadPrivacy();
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Failed to export data';
      toast({ title: 'Export failed', description: message });
    } finally {
      setExporting(false);
    }
  };

  const onDelete = async () => {
    if (deleteConfirm !== DELETE_CONFIRMATION_PHRASE) {
      toast({
        title: 'Confirmation required',
        description: `Type ${DELETE_CONFIRMATION_PHRASE} to continue.`,
      });
      return;
    }
    setDeleting(true);
    try {
      await deleteAccount({
        password: deletePassword,
        confirm: deleteConfirm,
      });
      clearToken();
      clearRefreshToken();
      toast({
        title: 'Account deleted',
        description: 'Your personal data was permanently removed.',
      });
      navigate('/signin');
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Failed to delete account';
      toast({ title: 'Deletion failed', description: message });
    } finally {
      setDeleting(false);
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

      <div className="card space-y-5 fade-in-up">
        <div>
          <h2 className="text-lg font-semibold">Privacy & data</h2>
          <p className="text-sm text-muted-foreground mt-1">
            Download a copy of your personal data, or permanently delete your
            account. Deletion cannot be undone.
          </p>
        </div>

        {preview && (
          <div className="text-sm text-muted-foreground grid grid-cols-2 sm:grid-cols-3 gap-2">
            <span>Categories: {preview.categories}</span>
            <span>Expenses: {preview.expenses}</span>
            <span>Recurring: {preview.recurring_expenses}</span>
            <span>Bills: {preview.bills}</span>
            <span>Reminders: {preview.reminders}</span>
            <span>Subscriptions: {preview.subscriptions}</span>
          </div>
        )}

        <div className="flex flex-wrap gap-3">
          <Button variant="outline" onClick={onExport} disabled={exporting || loading}>
            {exporting ? 'Preparing export...' : 'Download my data (ZIP)'}
          </Button>
        </div>

        {auditItems.length > 0 && (
          <div className="space-y-2">
            <Label>Recent privacy activity</Label>
            <ul className="text-sm text-muted-foreground space-y-1">
              {auditItems.map((item) => (
                <li key={item.id}>
                  {item.action} · {new Date(item.created_at).toLocaleString()}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div className="card space-y-5 border-destructive/40 fade-in-up">
        <div>
          <h2 className="text-lg font-semibold text-destructive">
            Delete account
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            This permanently removes your profile, expenses, bills, reminders,
            and related data. Type{' '}
            <code className="text-xs">{DELETE_CONFIRMATION_PHRASE}</code> and
            enter your password to confirm.
          </p>
        </div>
        <div className="space-y-2">
          <Label htmlFor="delete_confirm">Confirmation phrase</Label>
          <Input
            id="delete_confirm"
            value={deleteConfirm}
            onChange={(e) => setDeleteConfirm(e.target.value)}
            placeholder={DELETE_CONFIRMATION_PHRASE}
            autoComplete="off"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="delete_password">Password</Label>
          <Input
            id="delete_password"
            type="password"
            value={deletePassword}
            onChange={(e) => setDeletePassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>
        <div className="flex justify-end">
          <Button
            variant="destructive"
            onClick={onDelete}
            disabled={
              deleting ||
              loading ||
              !deletePassword ||
              deleteConfirm !== DELETE_CONFIRMATION_PHRASE
            }
          >
            {deleting ? 'Deleting...' : 'Permanently delete my account'}
          </Button>
        </div>
      </div>
    </div>
  );
}
