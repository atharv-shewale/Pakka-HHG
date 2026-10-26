# Pakka — Product Requirements Document

**Tagline:** Speak it. Clarify it. Confirm it. Prove what changed.  
**Submission:** Hacker House Goa 2026 — Wispr Flow Wildcard  
**Product type:** Voice-first, local-first web application  
**Status:** Implemented & Locally Verified MVP (Passes all 12 Acceptance Tests).

## 1. Executive summary

Pakka helps freelancers, students, independent workers, and small businesses turn informal work agreements into clear, reviewable records. A user describes a deal in ordinary language. Pakka captures the brief, highlights details that need confirmation, creates a structured agreement, records confirmations and work/payment check-ins, and produces a printable Proof File with a tamper-evident event history.

The MVP is intentionally local-first. It uses browser storage and the Web Crypto API; it does not move money, authenticate real-world identities, or claim legal enforceability.

## 2. Problem

Small jobs are often agreed through quick conversations or chats. The parties may later disagree about the amount, deadline, deliverables, what counts as completion, or whether payment was made. Reconstructing the agreement from scattered messages wastes time and erodes trust.

## 3. Target users

- Freelancers working on small, fixed-price jobs.
- Students doing paid design, development, tutoring, or event work.
- Local service providers and small businesses arranging work informally.

## 4. Product promise

“Turn a spoken work agreement into a clear record both sides can review, confirm, and verify for later reference.”

## 5. Primary user journey

1. Open Pakka and choose **Create agreement**.
2. Speak or type a natural-language brief, for example: “I’ll design 20 posters for Rahul for ₹4,000 by Friday. Payment after approval.”
3. Pakka places the transcript in a draft and extracts simple hints such as amount and possible deadline. The user reviews and edits structured fields.
4. Pakka highlights missing or vague fields: parties, deliverables, amount, deadline, acceptance criteria, and payment terms. The agreement cannot be activated until required fields are completed.
5. Review the summary and confirm the terms. The first event is added to the integrity log.
6. Record confirmations from the client and worker using a clearly labelled demo role switch. Append work-progress or payment check-ins.
7. Open the **Proof File** to see the final terms, event timeline, verification status, and an option to print or export JSON.
8. In demo mode, deliberately modify a saved log entry and run verification again. Verification must change from **Verified** to **Tampering detected**.

## 6. MVP requirements

### P0 — required

- A polished, responsive single-page dashboard titled **Pakka**.
- Agreement draft form with: client name, worker name, deliverables, amount/currency, due date, acceptance criteria, and payment terms.
- Voice-to-text entry when the browser supports the Web Speech API; language selection for English (India) and Hindi (India); always provide an editable text fallback.
- Simple, transparent parsing hints from the brief. Never silently treat guesses as confirmed agreement terms.
- Missing-field validation and a review/confirm step before activation.
- Local persistence across refreshes using `localStorage`.
- Agreement list with status and amount due.
- A detail view with client/worker role selector for **demo simulation**, confirmation controls, work check-in, payment status, notes, and timestamps.
- An append-only event log. Each event includes a previous hash and a SHA-256 digest calculated with `crypto.subtle` over a deterministic JSON representation.
- A verification action that recomputes every event hash and checks the previous-hash links.
- A conspicuous **Tamper demo** action that changes an existing event payload without recalculating its hash; verification must fail visibly afterward.
- A printable Proof File with agreement terms, event timeline, balance/payment state, and integrity result. Include print styles so the user can choose **Save as PDF** in the browser.
- Export agreement and event history as JSON.
- Three preloaded demo scenarios and a **Reset demo data** action.
- Empty, error, loading, and unsupported-microphone states handled gracefully.
- A persistent disclaimer: **Demo recordkeeping only. Not legal advice, identity verification, escrow, or payment processing.**

### P1 — only after all P0 tests pass

- English/Hindi spoken status messages using browser speech synthesis where available.
- A visually clear timeline and copyable integrity hash.
- Optional one-click sample data load from the welcome screen.

### Explicitly out of scope

- Real payments, escrow, wallet connection, blockchain or testnet deployment.
- Real identity verification, login, remote signing, or multi-device sync.
- Legal claims, automatic dispute adjudication, or guarantees that recorded statements are true.
- Cloud backend, external LLM/API calls, paid services, or complex NLP.
- A public share URL. The MVP supports print and JSON export only.

## 7. Data model

### Agreement

- `id`: unique local identifier.
- `clientName`, `workerName`: strings.
- `deliverables`: string.
- `amount`: non-negative number.
- `currency`: default `INR`.
- `dueDate`: ISO date or empty until completed.
- `acceptanceCriteria`: string.
- `paymentTerms`: string.
- `status`: `draft`, `active`, `completed`, or `disputed`.
- `createdAt`, `updatedAt`: ISO timestamps.
- `events`: ordered array of integrity-linked events.

### Event

- `id`, `type`, `actor`, `timestamp`, `payload`, `prevHash`, `hash`.
- `type` examples: `agreement_created`, `party_confirmed`, `work_checkin`, `payment_update`, `status_update`.
- Hash input must be deterministic: fixed field order or recursively canonicalized JSON, excluding the event's own `hash` and including `prevHash`.
- The first event uses a deterministic genesis value based on the agreement ID.

Do not mutate a confirmed agreement silently. Any later change to an agreement term must either be disallowed in the MVP or represented as a clearly labelled amendment event.

## 8. Safety, privacy, and integrity language

- Store data in the current browser only. Explain that clearing browser storage may delete records.
- Do not collect or transmit personal data to a server.
- The demo role switch simulates confirmation; it is not proof of who clicked.
- A local hash chain detects changes relative to saved hashes, but someone with full local access could alter both data and hashes. Do not describe it as blockchain, immutable storage, identity proof, or legally binding evidence.
- A successful verification means “the stored event chain matches its current hashes,” not “the agreement is true.”

## 9. UX requirements

- A first-time reviewer should understand the problem and start a sample deal without reading documentation.
- High contrast, clear hierarchy, large tap targets, readable forms, and responsive mobile layout.
- Show one primary action per state.
- Use visible statuses: Draft, Awaiting confirmation, Active, Completed, Disputed; integrity states: Not checked, Verified, Tampering detected, Verification unavailable.
- Never hide a missing term or verification failure behind a toast alone.
- Demo data must make the app useful immediately, but be clearly labelled as sample data.

## 10. Acceptance tests

1. The application starts locally using the README instructions without an API key or paid service.
2. The user can create an agreement with all required fields and see it after refresh.
3. An incomplete agreement is blocked from activation and lists the missing fields.
4. The mic control either records speech through a supported browser or displays a useful fallback; manual text entry always works.
5. Confirming terms appends an event and produces a successful verification result.
6. Each check-in/payment update appends another event linked to the previous hash.
7. The Proof File accurately reflects current agreement data and the event log.
8. JSON export contains the agreement and event chain.
9. The tamper demo changes a stored event but not its saved hash; subsequent verification reports failure.
10. Resetting sample data restores a working, verifiable demo.
11. The disclaimer is visible in the app and printable Proof File.
12. No claim of live escrow, blockchain settlement, legal enforceability, or identity verification appears in the UI or README.

## 11. Demo script (90–120 seconds)

1. Open the app and say: “Pakka turns informal work promises into clear, checkable records.”
2. Load a sample or dictate a brief for a poster-design job.
3. Show the missing acceptance condition or deadline and complete it.
4. Review and activate the agreement.
5. Switch the simulated role and confirm as the client and worker.
6. Add a work check-in and mark a partial payment.
7. Open the Proof File and point to the terms, timeline, amount, and Verified status.
8. Select **Tamper demo**, re-run verification, and show **Tampering detected**.
9. Finish by stating that the MVP is local-first and that its hash chain is tamper-evident recordkeeping, not legal or blockchain proof.

## 12. Definition of done

The MVP is done when all P0 acceptance tests pass, the core workflow can be demonstrated without relying on an external service, the repository has honest setup/limitations documentation, and the screen recording shows the real Wispr Flow-driven build process.
