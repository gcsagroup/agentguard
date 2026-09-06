[简体中文](mail-protection-design.md) | [繁體中文](mail-protection-design.zh-TW.md) | [English](mail-protection-design.en.md)

# Joint protection for email clients and webmail

Status: **design candidate; no email proxy or real mailbox integration has been implemented**. This iteration supplies architecture, an interaction preview and an acceptance plan. Existing desktop, browser or MCP results do not prove email protection.

## Goal and preferred approach

Cover receiving, reading, attachments and outbound email in both clients and webmail. Transparent means minimal day-to-day change after explicit authorization and setup, not zero-configuration decryption of all traffic.

For enterprise mail, prefer a **server-side inbound/outbound gateway supplemented by webmail and client integrations**. Personal accounts without tenant routing authority can only have an explicitly tested support matrix, not an unbypassable, all-device guarantee.

| Integration | Intended responsibility | Boundary |
| --- | --- | --- |
| Enterprise gateway | Inspect before delivery/submission; quarantine, reject or hold for approval | Administrator routing authorization required; internal mail, aliases, forwarding and bypass paths need separate tests |
| Webmail adapter | Prompt injection, link clicks, attachment upload and pre-send review | Test each site/browser version; DOM buttons alone do not cover service workers, direct APIs or all uploads |
| Client adapter | Configurable IMAP/SMTP proxy or official pre-send extension | Other Outlook protocols and unsupported clients are not automatically covered by IMAP/SMTP |
| Mailbox API connector | Synchronization, supplemental scanning, quarantine and status reconciliation | Post-notification scanning is not pre-delivery interception; mutation scopes require separate authorization |

Microsoft 365 connectors and Google Workspace inbound/outbound routing make the enterprise path plausible, but each tenant's configuration still needs acceptance. [Microsoft connectors](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/use-connectors-to-configure-mail-flow), [Google inbound gateway](https://support.google.com/a/answer/60730?hl=en-GB), [Google outbound gateway](https://support.google.com/a/answer/178333?hl=en)

Apple MailKit exposes a pre-send callback; Outlook Smart Alerts supports send events subject to client, deployment and offline limitations. These are candidate integration points, not shipped AgentGuard capabilities. [MailKit](https://developer.apple.com/documentation/mailkit/mecomposesessionhandler/allowmessagesendforsession(_:completion:)), [Outlook Smart Alerts](https://learn.microsoft.com/en-us/office/dev/add-ins/outlook/onmessagesend-onappointmentsend-events)

## Trust and execution

The proposed path is: authenticated integration → immutable send snapshot → shared policy → reject/hold/allow this version → controlled submission → receipt reconciliation. Inbound enterprise messages also pass through the policy path before delivery.

Bodies, HTML, attachment names, links and model analysis are untrusted data. Claims such as “the administrator approved this” cannot grant authorization or change configuration. Models supply risk signals, never final authority to send, alter recipients or disable checking.

Decode MIME, derive displayed HTML text and Unicode matching views, then inspect attachments with bounded size, expansion ratio, nesting, time and redirects. Encrypted, malformed or unsupported content must show “cannot inspect” and follow the authorized quarantine/manual-review policy, never a green pass. S/MIME needs the appropriate decryption capability; collecting users' private keys is not a default transparency mechanism. [S/MIME](https://www.rfc-editor.org/info/rfc8551/)

## Binding an outbound approval

The proposed snapshot binds account/tenant, integration identity, sender, every To/Cc/Bcc recipient, subject, semantic body summary plus raw-content hash, each attachment's content hash, policy version, expiry and a single-use request ID. Human-readable summaries do not replace submitted-byte verification; transport-added headers are modeled separately from editable content.

- Recompare the snapshot at submission. Recipient, body, attachment or policy changes invalidate the previous approval.
- Compare addresses using mailbox semantics; separate domains from display names, do not blindly lowercase the entire address, and do not omit Bcc.
- Timeout, disconnect, identity changes or failed revalidation must not auto-send. For already-submitted mail with a missing receipt, show “outcome pending verification” and reconcile before retrying.
- Approval, submission and delivery are distinct states. IMAP synchronization, SMTP acceptance and API acceptance are not proof that the recipient received the message.

Shared policy, privacy analysis, encrypted audit and confirmation mechanisms may be reused after review. The current `guard-gateway` is a cooperative MCP executor; it has no mailbox connector, MIME pipeline or mail-delivery receipt path. Concurrent mail queues, approval binding and delivery idempotency require dedicated implementation and tests.

## Authorization and privacy

Use provider-supported authorization and explain read, send and quarantine/mutation scopes separately. Store credentials in OS-protected storage, not logs or frontend persistence. Revocation or insufficient scopes must degrade protection and stop affected operations, never fall back to plaintext passwords or bypass checks. [Gmail OAuth](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol), [Microsoft OAuth](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth)

Retain minimized findings, rule IDs, hashes and receipts by default, not full messages. Storing quarantined originals requires separate opt-in, encryption, retention limits and auditable deletion. Credentials, queues and storage must be tenant-isolated. Attachment sandboxes must not inherit the user's network identity or local credentials.

## Entry points and truthful status

Proposed navigation: Active protection → Email protection.

1. **Connections and coverage:** choose enterprise routing or personal accounts; explain permissions, supported clients/sites and gaps. Mark a path verified only after real test mail succeeds.
2. **Pending approvals:** expose external recipients, reasons and attachment summaries. The review box starts unchecked; reject is directly available. Changes, expiry or disconnect invalidate the current approval.
3. **Activity:** distinguish checked, rejected, pending, approved, submitted, uncertain and uncovered; one global toggle must not imply universal coverage.

Protection settings → Email contains account management, inspection/quarantine policy, minimization/retention, diagnostics and disconnection. Every integration has independent health. Turning off a browser extension must not invent a server-gateway state.

The preview uses synthetic messages and local UI state only. It does not read/write mailboxes or make SMTP/API requests. It can validate interaction, copy and approval invalidation, not backend inspection, actual upload blocking or delivery.

## Implementation gates

| Phase | Work | Required evidence |
| --- | --- | --- |
| M0 | Design and preview | Wide/narrow layouts and keyboard interaction; no false live-protection claims |
| M1 | Local fake SMTP receiver, MIME fixtures, approval binding and audit | The mail suite below; receiver count stays zero after reject, expiry or mutation |
| M2 | One authorized test tenant and one site/browser pair | Inbound, outbound, internal and bypass coverage; traceable receipts and no blind retries |
| M3 | Client and personal-account integrations | Versioned online/offline, upload and uncovered-path support matrix |
| M4 | Release | Tenant isolation, recovery, signing, full end-to-end evidence and rollback |

This iteration completes M0 documentation and preview checks only. M1–M4 remain incomplete.

## Mail-specific local acceptance suite — not yet executed

| ID | Representative case | Required result |
| --- | --- | --- |
| MAIL-01 | Plain text, benign Unicode, ordinary attachments | Valid delivery without language-based false positives |
| MAIL-02 | Hidden HTML instructions, invisible encodings, forged authority | Treated only as untrusted content, never extra execution authority |
| MAIL-03 | Sensitive attachment to external To/Cc/Bcc | Zero deliveries before approval; all recipients reviewable |
| MAIL-04 | Recipient/body changes or same-name attachment replacement | Prior approval invalid; only the approved snapshot can be submitted |
| MAIL-05 | Timeout, disconnect, account revocation, approval-process restart | Unsubmitted mail stays unsent; recovery requires revalidation |
| MAIL-06 | Double approval, concurrent IDs, SMTP drop, missing API receipt | No duplicate submission; uncertain outcomes reconciled |
| MAIL-07 | Archive bomb, oversized attachment, S/MIME, parse error | Bounded analysis; uninspectable content cannot pass silently |
| MAIL-08 | Web shortcuts, early upload, direct API, disabled extension | Verified support matrix; bypass shown as a gap |
| MAIL-09 | Same IDs across tenants, replayed approval token | Reject cross-account/tenant/session authority |
| MAIL-10 | Insufficient scopes, TLS failures, internal forwarding/aliases | No weaker authorization or certificate checks; routing tested separately |

M1 reports must include real receiver counts, submission logs, snapshot binding, minimized audit and process exit codes. Existing generic evaluations or browser-extension tests, and this preview, cannot be counted as MAIL-case passes.
