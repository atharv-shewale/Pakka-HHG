# Pakka — Wispr Flow / Antigravity Spoken Prompt Sequence

Use Wispr Flow to dictate each prompt into Antigravity. Keep the actual build process visible in the screen recording. Use Planning mode for Prompt 1; after reviewing the plan, execute prompts in order. Do not type code manually. Keyboard shortcuts, app navigation, and approving commands are fine if the challenge rules permit them.

## Prompt 1 — Product plan and constraints

> I want to build a polished web app called Pakka for the Hacker House Goa Wispr Flow wildcard. It helps freelancers and small service providers turn informal work promises into clear agreements and a tamper-evident history. Before coding, produce a short implementation plan and acceptance checklist. Use only HTML, CSS, and vanilla JavaScript, with no backend, no build step, no external APIs, no paid services, and no dependency installation. It must run from a local HTTP server. The actual product must remain small enough to finish today. The core is agreement review, missing-term checks, simulated party confirmations, work/payment check-ins, a SHA-256 hash chain, verification, a tamper demo, a printable Proof File, and JSON export. Never claim real escrow, blockchain, legal enforceability, or identity verification. Make all data clearly demo/local-first. Wait for my approval before implementing.

## Prompt 2 — Scaffold the interface

> Implement the approved plan. Create index.html, styles.css, and app.js. Build a responsive, polished single-page dashboard with a clear hero, a list of agreements, a create-agreement form, a selected-agreement detail area, a timeline, and a Proof File view. Use a distinctive but professional visual style, strong typography, generous spacing, accessible contrast, clear buttons, and excellent empty/loading/error states. Add sample data and a reset-demo button so the reviewer can try it immediately. Keep the code simple and dependency-free. Make sure the page works at desktop and mobile widths. Start the local server and inspect it in the browser before continuing.

## Prompt 3 — Agreement creation and missing-term checks

> Implement the agreement workflow. Required fields are client name, worker name, deliverables, amount in INR, due date, acceptance criteria, and payment terms. Add a large brief input with a microphone button. If the browser supports the Web Speech API, support English India and Hindi India; otherwise show a helpful message and keep text entry fully usable. The transcript should fill an editable brief field, never silently finalize terms. Add transparent, best-effort parsing hints for common rupee amounts and simple deadline phrases, then let the user correct every structured field. Before activation, display missing or vague terms and block activation until required terms are filled. Add examples and field-level validation. Persist the agreements and UI-safe state in localStorage, and ensure saved records survive refresh.

## Prompt 4 — Confirmation and check-in workflow

> Add the agreement lifecycle. Support Draft, Awaiting confirmation, Active, Completed, and Disputed states. Once an agreement is activated, do not silently mutate its core terms. Add a clearly labelled demo role selector for Client and Worker, with separate confirm buttons and timestamps. Add a work check-in with a note and a payment update, including amount paid and amount remaining. Every confirmation, check-in, payment update, or status change must append an event to that agreement's ordered event history. The interface must state that role switching simulates both parties and is not authentication or a digital signature. Keep the demo easy to operate in under two minutes.

## Prompt 5 — SHA-256 integrity chain and tamper test

> Implement an actual local tamper-evident event chain using the browser Web Crypto API. Each event must contain id, type, actor, timestamp, payload, prevHash, and hash. Use deterministic/canonical JSON for the hash input, excluding the event's own hash and including prevHash. Start the chain from a deterministic genesis value that includes the agreement ID. Use crypto.subtle.digest with SHA-256 and handle an unavailable crypto API gracefully. Add a Verify integrity button that recomputes each event hash and checks each prevHash link. Show a clear green Verified state on success and a high-contrast Tampering detected state on failure; do not communicate this only through a temporary toast. Add a clearly labelled Tamper demo button that intentionally modifies an existing event payload without updating its saved hash, then re-runs verification and visibly fails. Reset demo data must restore a valid chain. Test both success and failure states in the browser.

## Prompt 6 — Proof File, print, and JSON export

> Build a dedicated Proof File view for the selected agreement. Include the parties, deliverables, amount/currency, deadline, acceptance criteria, payment terms, status, total paid, amount remaining, and a chronological event table with actor labels and timestamps. Display the integrity verification result and explain that verification checks the stored hash chain, not whether the agreement is true or legally enforceable. Add Export JSON for the agreement plus events. Add a Print / Save as PDF action using window.print and print CSS that hides navigation and controls while keeping all important record information. Do not create a fake public share URL. Make the Proof File look professional when printed.

## Prompt 7 — Hardening and acceptance test

> Test the application end to end in the browser. Verify: a new agreement can be created; incomplete terms block activation; all fields can be corrected; records survive refresh; confirmation and check-ins append events; successful verification works; tampering causes verification to fail; reset restores the demo; JSON export downloads valid JSON; the Proof File prints cleanly; and the application remains usable without microphone permission. Fix failures with the simplest changes possible. Check browser console errors and test one narrow mobile viewport. Do not add new features until all required tests pass. If anything cannot be completed, tell me honestly and leave the rest stable.

## Prompt 8 — Documentation and repository polish

> Create README.md and PRD.md in the repository based on the implementation that actually exists. README must include the problem, target users, features, exact local run command, demo steps, stack, privacy model, limitations, and integrity explanation. PRD must list product requirements and acceptance tests, marking anything unimplemented as incomplete instead of claiming it works. Add screenshots only if the app can be captured reliably. Check that no secrets, API keys, fabricated results, or misleading claims exist. Do not say the app is production-ready. Initialize git if needed, review git status, make a sensible first commit, and show me the exact repository state.

## Prompt 9 — Final demo rehearsal

> Help me rehearse a two-minute demo without changing working features. Prepare a sequence that starts from a fresh reset: load a sample agreement, show a missing-term check, confirm the agreement, add a work check-in and partial payment, open the Proof File, show Verified, trigger Tamper demo, and show Tampering detected. Confirm that the demo uses no external API or real money. Ensure every visible feature works from a clean browser load. Suggest only essential fixes; do not refactor or add stretch features.

## If time is running out

Prioritize Prompts 1–3, then Prompt 5, then enough of Prompt 4 and Prompt 6 to demonstrate one complete deal and the integrity failure. Skip spoken replies, fancy animations, and anything resembling a blockchain or escrow integration. A stable, honest demo is stronger than half-finished complexity.

## Suggested voice dictation rhythm

- Dictate one prompt at a time and inspect the transcript before submitting it.
- Let the agent plan before approving a large change.
- After each milestone, dictate a browser test request and ask for a clear commit message.
- Keep the recording running through the real prompts, build, fixes, tests, and final demo.
- Do not edit code manually during the build. If something fails, dictate the error and the desired fix through Wispr Flow.
