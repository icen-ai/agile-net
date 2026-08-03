# Sync & Backup

Sync & Backup answers one question: **when you switch devices, how does your configuration follow
you?** It packs application settings, custom rules and hosts, and the subscription list with override
scripts into a versioned archive, uploaded through a channel of your choice; on another device, enter
the same channel configuration and pull to restore in one click. Three channels, pick any one:

- **WebDAV**: Jianguoyun (Nutstore), Nextcloud, etc. — the easiest personal option
- **S3-compatible storage**: AWS S3, MinIO, Backblaze B2, Cloudflare R2 — for users who already have object storage
- **Manual file import/export**: no network service required — a USB drive or any file transfer through chat apps works

Entry point: **Settings → Sync & Backup**.

## What Gets Synced — and What Doesn't

| Synced | Not Synced |
| --- | --- |
| Application settings (role switches, preferences) | Web remote-access password (a per-machine secret, set on each machine) |
| Custom rules and hosts | mihomo control-plane secret (a per-machine random value; migrating it is meaningless) |
| Subscription list and override scripts | Local credentials (fan-in tokens live in the system credential store and do not travel with the archive) |

## Quick Start (Jianguoyun WebDAV example)

First device (the uploader):

1. Open Settings → Sync & Backup, choose **WebDAV** as the channel, and fill in Jianguoyun's WebDAV URL, account, and **app password** (see "WebDAV in Detail" below for how to get one).
2. Optionally set a 4-digit PIN (leave empty for no encryption; trade-offs in "Encryption Notes").
3. Click "Upload Now". On success the version number increments (e.g. v1 → v2), meaning the archive has landed remotely.

Second device (the restorer):

1. Go to Settings → Sync & Backup as well, and enter the **exact same** channel configuration and PIN.
2. Before clicking "Pull & Restore", read the version comparison first: "Remote is newer" means you can safely pull.
3. Confirm the restore. The app first backs up the current configuration locally, then applies the archive and **restarts automatically** to take effect.

Both devices can upload as needed afterwards; designating one primary machine for uploads is recommended — see "FAQ" for why.

---

## Channel in Detail: WebDAV

| Field | Meaning | Example |
| --- | --- | --- |
| URL | WebDAV directory URL; the archive is always placed under this directory | `https://dav.jianguoyun.com/dav/AgileNet/` |
| Account | Service account (for Jianguoyun, the registered email) | `you@example.com` |
| Password | The **app password**, not your login password | 16-character app authorization code |

**How to get a Jianguoyun app password**: log in to the Jianguoyun web version → account (top right) →
Account Info → Security → "Third-party App Management" → add an app password. Keeping the archive in a
dedicated directory (e.g. `/dav/AgileNet/`) is recommended; the app attempts to create the directory if
it does not exist.

**Nextcloud**: the WebDAV URL looks like `https://<your-domain>/remote.php/dav/files/<username>/AgileNet/`;
here too, use a Nextcloud "app password" (Settings → Security → App & device sessions) rather than your
main password.

The remote file name is fixed as `agile-net-sync.json`, placed under the configured URL directory.

## Channel in Detail: S3-Compatible Storage

| Field | Meaning | MinIO Example | Cloudflare R2 Example |
| --- | --- | --- | --- |
| Endpoint | Service address (without the bucket) | `http://192.168.1.10:9000` | `https://<accountid>.r2.cloudflarestorage.com` |
| Bucket | Bucket name | `anet-backup` | `anet-backup` |
| Access Key / Secret Key | Access credentials | Created in the MinIO console | Created via R2 "Manage API Tokens" |
| Region | Region; required by some services | `us-east-1` (MinIO default) | `auto` |
| Prefix | In-bucket path prefix; optional | `sync/` | `sync/` |

The archive lands at `bucket/prefix/agile-net-sync.json`.

**Least-privilege advice**: create a dedicated bucket and a dedicated AK/SK pair for sync, granting
read/write on that bucket only (`s3:GetObject` / `s3:PutObject` / `s3:DeleteObject`, scoped to
`arn:aws:s3:::anet-backup/*`); never reuse a high-privilege root account key.

## Channel in Detail: Manual Import/Export

No remote needed — work directly with files:

- **Export**: click "Export Archive" to get an `agile-net-sync.json` file — copy it to a USB drive or send it to another device through a chat app.
- **Import**: on the target device, click "Import Archive" and select the file. The effect is identical to pull-and-restore (a local automatic backup is made first, then a restart applies it).

The file name is fixed and carries no version number; **the version lives inside the file**. Before
importing, the app reads out the archive version, timestamp, and source device name for your
confirmation. A PIN-protected archive stays encrypted after export, and importing it requires the same PIN.

---

## Reading Version Numbers and Timestamps

Every archive carries three pieces of metadata: **version** (integer, +1 per upload), **timestamp**
(upload time), and **device name** (the uploader's machine name).

- **Telling whether an upload succeeded**: check whether the version incremented (e.g. v3 → v4) and the timestamp refreshed.
- **Version comparison before pulling**:

| Result | Meaning | Advice |
| --- | --- | --- |
| Remote is newer | The remote version is higher than local | Safe to pull |
| Up to date | Both sides match | Nothing to do |
| Local is newer | The local version is higher than remote (this machine has unpushed changes, or the remote was overwritten by an older archive) | Don't pull — confirm which side is correct first |

## Encryption Notes and Security Advice

Set a **4-digit PIN** and archives are uploaded encrypted with AES-256-GCM (the key is derived from the
PIN via PBKDF2); leave it empty and archives upload in plaintext.

**Understand the real strength of a 4-digit PIN**: with only ten thousand combinations it is
**obfuscation-grade protection** — it stops someone casually browsing your cloud-drive directory, but
not a determined attacker who downloads the archive and brute-forces it offline. Therefore:

- The archive contains your subscription list; if the subscription links themselves are sensitive, **use a private WebDAV directory or a self-managed bucket** — never place an unencrypted archive in a shared/public directory.
- There is **no PIN recovery**: a forgotten PIN means the archive cannot be decrypted — you can only set a new PIN on a device that still has the configuration and re-upload.
- The PIN is entered per device and never stored remotely; after changing the PIN you must re-upload — old archives remain encrypted with the old PIN.

## Restore and Rollback

**Restoring never discards local configuration outright**: before every pull/import restore, the app
automatically backs up the current configuration in full to:

```
~/.agile-net/backup-pre-restore-<timestamp>/
```

After the restore completes, the app **restarts automatically** to apply the configuration.

**Manual rollback**: if the restore result is unsatisfying, quit AgileNet, copy the files from the
backup directory with the corresponding timestamp back over `~/.agile-net/`, and start again. Backup
directories are ordered by timestamp, so you can recover the state before any restore in history;
delete older directories yourself if space runs tight.

---

## FAQ

**Two devices changed the configuration at the same time — how are conflicts handled?**
Sync is "last write wins": the remote keeps exactly one latest archive, later uploads overwrite earlier
ones, and there is no field-level merge. Designate one primary machine for uploads and let the rest
only pull; if you must change important configuration on another device, upload immediately after the
change, and avoid editing on two devices in parallel.

**Device migration checklist**:

1. Old device: confirm the latest archive has been uploaded (the version is current).
2. New device: install AgileNet → enter the same channel configuration and PIN → pull & restore.
3. Re-create the pieces that **do not travel with the archive**, one by one: set the Web remote-access password again; re-login/re-import credentials (node login credentials, fan-in tokens); the mihomo control-plane secret is generated automatically by the new device — nothing to do.

**Troubleshooting sync failures**:

| Symptom | Likely Cause | Resolution |
| --- | --- | --- |
| 401 / authentication failure | Wrong account or app password (WebDAV given the login password instead of an app password; S3 AK/SK swapped) | Regenerate the app password / double-check credentials |
| 403 / permission denied | The S3 policy does not cover the bucket or prefix; the WebDAV directory is not writable | Review the policy per the "least-privilege advice" |
| Network timeout | Under a proxy environment, sync traffic was sent into a proxy that is itself unavailable | Sync requests always go direct, bypassing the system proxy; check local egress and DNS — `anet tool diag <host> 443` localizes the failing layer |

For general troubleshooting of other network failures, see [Troubleshooting and Diagnosis](#/guides/troubleshooting) and [Self-Diagnosis](#/guides/doctor).
