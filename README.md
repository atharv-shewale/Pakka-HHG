# Pakka — Speak it. Clarify it. Confirm it. Prove what changed.

Pakka is a voice-first, local-first agreement tracker for small freelance and informal work. It helps two parties record what was agreed, track confirmations and payment/work updates, and produce a printable Proof File with a tamper-evident event history.

> **Important:** This is a demonstration of recordkeeping, not legal advice, identity verification, escrow, payment processing, or blockchain storage. A verified local hash chain only confirms that the stored entries match their current hashes; it does not prove that the statements are true or identify who made them.

## Problem

Small jobs are often agreed in a call or a quick chat. Deliverables, price, deadlines, acceptance criteria, and payment terms can be remembered differently later. Pakka turns the agreement into a structured record that both sides can review and update through a simple timeline.

## What it does

- Captures a spoken brief where browser speech recognition is available, with an editable text fallback.
- Lets users review structured terms and flags missing details before confirmation.
- Saves agreements locally in the browser.
- Records simulated client/worker confirmations, work check-ins, and payment updates.
- Links events with SHA-256 hashes and verifies the event chain.
- Includes a tamper demo that changes an event and makes verification fail visibly.
- Generates a print-friendly Proof File and JSON export.
- Includes sample data so a reviewer can try the workflow quickly.

## Quick start

This project is intended to have no backend, external API, or paid dependency. Once the code has been generated and tested in the project folder, start a local server from that folder:

```bash
python -m http.server 4173
```

Then open `http://localhost:4173` in a modern browser. If the generated app uses a different port or start command, follow the command shown by the development agent and update this section accordingly. The app should be served from localhost rather than opened as a `file://` URL so browser security APIs behave consistently.

## Demo in under two minutes

1. Load one of the sample agreements.
2. Review the amount, deliverables, deadline, acceptance criteria, and payment terms.
3. Confirm the agreement through the clearly labelled simulated roles.
4. Add a work check-in and a payment update.
5. Open the Proof File and inspect the timeline and **Verified** integrity status.
6. Use **Tamper demo** and verify again. The status should become **Tampering detected**.
7. Print/save the Proof File as PDF or export the record as JSON.

## Privacy and limitations

- Records are stored in the browser's local storage on the current device/profile. Clearing site data can delete them.
- No remote backup or multi-device sync is included.
- The client/worker role selector is a demo simulation, not authentication or a digital signature.
- The Web Speech API varies by browser and may require microphone permission. Text entry must remain usable if speech recognition is unavailable.
- Parsing hints are best-effort. Users must review and correct every term before confirmation.
- A hash chain is tamper-evident only relative to the hashes that are retained. A sophisticated user with full local access could alter both the entries and hashes.
- The application does not move money, hold funds, connect a wallet, interact with a blockchain, or determine legal rights.

## Built with

- HTML, CSS, and vanilla JavaScript (intended MVP stack)
- Browser `localStorage` for local persistence
- Web Speech API for optional speech input
- Web Crypto API (`crypto.subtle`) for SHA-256 event hashes
- Browser print functionality for the Proof File

The final implementation should update this section if the generated code differs from the intended stack. Do not claim a technology is implemented unless it is present and tested in the repository.

## Integrity model

Each event stores its type, actor label, timestamp, payload, previous hash, and SHA-256 hash. The first event links to a deterministic genesis value for the agreement. Verification recomputes the hash for every event and checks the previous-hash chain. The tamper demo intentionally changes a stored event without recalculating the saved hash; verification should fail.

This provides a useful teaching/demo mechanism for tamper-evident logs. It is not a public blockchain, trusted timestamp, legal signature, or proof of identity.

## Built for the Wispr Flow wildcard

The project should be scaffolded, implemented, tested, and documented using Wispr Flow voice dictation into the coding agent, with a continuous screen recording that shows the actual process. This README is a reference outline: dictate its content through Wispr Flow during the recorded workflow rather than manually inserting prewritten code or files if the task requires the project to be built entirely by voice.

## Suggested repository structure

```text
pakka/
├── index.html
├── styles.css
├── app.js
├── README.md
└── PRD.md
```

## Status

**Implemented and Locally Verified:** All core MVP requirements (P0) and spoken audio cues (P1) have been implemented and tested end-to-end in the browser. The application runs locally with zero build step and zero backend dependencies. It has been verified against the acceptance checklist:
- [x] Spoken brief dictation and transparent hint extraction
- [x] Structured agreement creation and missing-terms validation
- [x] Draft terms correction and amendment re-hashing
- [x] Dual-party simulated confirmation workflow
- [x] Work check-in milestones and payment ledger tracking
- [x] Deterministic SHA-256 hash chaining via browser Web Crypto API
- [x] Live integrity verification engine
- [x] High-contrast Tamper Demo with fault localization
- [x] Dedicated printable Proof File (`window.print`) and JSON export
- [x] Local persistence surviving browser refresh with full demo reset
