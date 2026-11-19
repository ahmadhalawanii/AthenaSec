# Approvals and response modes

## Approvals
When the policy says approval is required, an authorised person approves or rejects the exact proposed action on the Approvals page. The approval is tied to that action, is time limited and can be used once. A typed yes in chat is not an approval. A rejected or expired request is recorded and the action does not run.

## After approval
An approval does not by itself show the action has run. Execution, independent verification and any rollback or expiry are recorded separately.

## Response modes
SHADOW mode investigates and records what AthenaSec would do, without acting. SUPERVISED mode needs a person to approve risky response actions. AUTONOMOUS mode lets AthenaSec run actions its policy allows, within its safeguards.

## The kill switch
When autonomous response is disabled, Cortex execution stops while investigation, case management, reporting and the audit log keep working. Protected targets and the kill switch apply whatever anyone types into chat.
