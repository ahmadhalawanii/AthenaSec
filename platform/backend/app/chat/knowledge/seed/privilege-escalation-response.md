# Privilege escalation response

## What it is
Privilege escalation is when an account or process gains more access than it was given, for example a normal user running commands as an administrator. It is often a later step after an attacker already has a foothold.

## Evidence to check first
Identify the account, the host and the exact command or change that raised privileges. Check what that account did before and after. Look for new administrator accounts, changed group membership and new scheduled tasks or services.

## What not to conclude
An escalation alert shows an attempt or a change. Confirm in the recorded events that it actually succeeded before treating the host as compromised.

## Containment options
Isolating the host or disabling the account are strong actions. Both are proposed responses in AthenaSec and go through the action policy and, where required, a person's approval. Protected targets are never acted on automatically.

## After the alert
Record the account, host, command and outcome in the case, and note any accounts that should be reviewed.
