# Security

Chaperone holds credentials and decides what an AI agent may do with them. A flaw here matters.

## Report a problem

Do not open a public issue for a security problem. Use GitHub's private report:
**Security → Report a vulnerability** on this repository. Say what you did, what happened and
what you expected. You will get a reply.

## What is in scope

- An agent reaching a credential, or acting without the check or approval it should have needed.
- An approval that can be forged, replayed or shown as something other than what runs.
- A ledger entry that can be changed or removed without the chain check failing.
- A secret printed or logged.

## What is not yet proven

This is a young project built for one small team. See "Status" in the README for the parts that
have tests but have not yet run against the real service.
