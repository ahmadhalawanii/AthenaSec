# Brute-force alert response

## What it is
A brute-force attempt is repeated guessing of passwords or other credentials against one account or many. Many failed sign-ins from one source address is the usual sign. A pile of failures does not mean anyone got in.

## Evidence to check first
Look at the source IP address, the number of failed sign-ins and the time window, and which accounts were targeted. Check whether any successful sign-in from the same source followed the failures. Compare with earlier alerts from the same address.

## What not to conclude
Do not say an account was compromised unless a successful sign-in from the attacker is recorded. Failures alone show an attempt, not a breach.

## Containment options
Temporarily blocking the source address is the usual containment. In AthenaSec a block is a proposed response: the action policy decides whether it is allowed automatically, needs a person's approval, or is not allowed. Chat cannot approve it. Reset or lock the targeted account only through your normal account process.

## After the alert
Record what was seen and what was done in the case. If a block was applied, confirm it was verified and note when it expires.
