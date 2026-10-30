# Gaps between the policy PDF and the app

For the next revision of `design/agent-action-policy.pdf` (Agent Action Catalogue and Approval Policy, Oct 8, 2026, 10 pages). Each entry gives the gap, where the PDF says it, what the app does now, and a suggested fix. The PDF is the authority; where it is silent or two places disagree, the app made a choice, and that choice is what is described here.

This file is self-contained. The reasoning behind the app's choices is in `design/plan-policy.md`.

## The gaps (19)

### 1. "Tier" means two things
- **PDF:** pages 1 and 5 use Tier 1, 2 and 3 for action tiers (allowed, approval-required, prohibited). Page 2 uses the same words for asset criticality (Tier 1 critical, Tier 2 business, Tier 3 standard). Page 4 says "asset Tier 2 or 3 only" and page 5 says "Tier 1 assets are out of scope", next to "Tier 2 actions".
- **App now:** action tiers are "Tier 1/2/3". Assets are "Critical / Business / Standard".
- **Suggested fix:** use one word for each. Keep "Tier" for actions and rename the asset scale (for example Critical, Business, Standard), then reword page 4 ("asset is not Critical") and page 5 ("a Critical host goes to Tier 3 handling").

### 2. Reputation exists only for external IPs
- **PDF:** page 2 gives Reputation a 0.00 to 1.00 scale and a weight of 0.25. Page 3 says `check_ip_reputation` is used only when the alert involves an external IP.
- **App now:** an alert with an internal source gets reputation 0. Without reputation the other three inputs total at most 75 (0.35 + 0.25 + 0.15 of 100), so a purely internal attack can never reach the isolation floor of 85. ALT-004, a kernel exploit from 10.0.7.51, scores 52.
- **Suggested fix:** say what Reputation is for an internal source. Options: 0, a neutral value, or reweight the other three inputs when R does not apply.

### 3. Risk 40 to 59 with low confidence: page 3 against page 6
- **PDF:** page 3 says `monitor` is used for "risk under 40, or risk 40-59 with low confidence". The page 6 diagram sends "40-59 or conf < 0.50" to "Investigate further".
- **App now:** follows the diagram. `monitor` is only for risk under 40. Low confidence at risk 40 or more investigates.
- **Suggested fix:** make the two agree. The diagram is the more complete of the two, so change the `monitor` row on page 3.

### 4. The ladder has no row for risk 70+ that fails its Tier 2 row
- **PDF:** the page 6 diagram lists "risk 60-69" for alert and ticket. Risk 70 or more with confidence below 0.80 matches no row.
- **App now:** falls to the next outcome below ("create alert and ticket"), as the page 6 text says it should.
- **Suggested fix:** change the label to "risk 60 or more, when nothing above applies".

### 5. `suspend_user_session` is never an outcome
- **PDF:** page 4 defines `suspend_user_session` as a Tier 2 action. Page 1 and page 6 list five outcomes, and none of them recommends a session suspension.
- **App now:** the action is catalogued, guarded and approvable, but the agent never recommends it.
- **Suggested fix:** add a sixth outcome ("recommend session suspension") to the ladder with its position, or say it is recommended only through a policy.

### 6. Isolation "then re-review" and the undefined `path`
- **PDF:** page 4 says "Default 2 h, max 4 h, then re-review". Page 1 says every Tier 2 action has an automatic expiry. The `path` parameter of `isolate_host(host, path)` is never defined.
- **App now:** the host reconnects at expiry (marked as an assumption in the catalogue). The path is `edr_network_isolation`.
- **Suggested fix:** state what happens at 4 h (reconnect, or stay isolated until a person decides), and list the allowed values of `path`.

### 7. "Narrower scope" has no meaning
- **PDF:** page 8 says Approve with changes "executes with a shorter duration or narrower scope".
- **App now:** an approver can only shorten the duration.
- **Suggested fix:** define scope for each Tier 2 action (for example one account instead of several), or remove the words.

### 8. A timed-out isolation escalates to the person who must approve it
- **PDF:** page 5 and page 8 say no reply means "escalated to the SOC lead". Page 4 says the SOC lead is the approver for isolation.
- **App now:** sends a second notice to all Administrators.
- **Suggested fix:** name who gets the escalation when the SOC lead is the approver (a second lead, a manager, or an on-call role).

### 9. "High-severity alert to the SOC lead" has no format
- **PDF:** page 5, layer 3: every rejected attempt "raises a high-severity alert to the SOC lead". There is no severity scale for alerts the system raises about itself, and no format.
- **App now:** logs the event in Demo mode. The notice itself is planned for the audit-log work.
- **Suggested fix:** state the severity value, the channel, whether one alert per attempt or one per burst, and what the SOC lead is expected to do.

### 10. A policy's risk threshold against the catalogue floor (closed by the whitelist and blacklist model)
- **PDF:** page 2 says a Tier 2 recommendation needs a matching policy. Pages 4 and 6 give a floor per action (70, 85, 75). Nothing says how a policy's own threshold relates to that floor.
- **App now:** the IF/THEN policies are gone. Each whitelisted Tier 2 action has a Minimum risk that can be raised above the PDF's floor but never lowered (block_ip 70, isolate_host 85, suspend_user_session 75); a save below it is refused with the PDF's number. The old POL-004 threshold of 60 never took effect and is gone.
- **Suggested fix:** state the rule: "a policy may raise the floor but never lower it".

### 11. "Investigate further" is an outcome but not an action
- **PDF:** page 6 has "Investigate further: Tier 1, more evidence, re-score". Page 3's Tier 1 table has no action for it.
- **App now:** the outcome exists; no catalogue row backs it.
- **Suggested fix:** add a Tier 1 row (for example `request_more_evidence(alert_id)`) or say which existing Tier 1 actions it uses and when it re-scores.

### 12. Approval modes have no counterpart in the PDF (closed by the whitelist and blacklist model)
- **PDF:** a Tier 2 action always needs a named human (page 4). Page 10 says the Response Policies page "shows the three tiers". There is no "approval mode" and no "Automatic".
- **App now:** a whitelisted action is Automatic or Needs approval. A Tier 2 action is never Automatic (its Automatic option is disabled and a save that sets it is refused), and "who approves" is the approver each action names, which a policy can only raise (isolate_host stays SOC lead or higher).
- **Suggested fix:** replace the three modes with the approver each action names, or define the modes in the PDF and say Automatic applies to Tier 1 only.

### 13. The page 7 example does not match the scoring
- **PDF:** the example scores risk 82 for the ALT-001 evidence, calls the target "a Tier 3 VPN gateway user pool", and writes times with `+04:00`.
- **App now:** scores ALT-001 at 77 with the page 2 formula, calls the asset class Business, and keeps demo times as local time with no zone.
- **Suggested fix:** recompute the example from the formula, use the asset wording from fix 1, and decide whether times carry a zone.

### 14. `model_version` has no value
- **PDF:** page 9 lists `model_version` ("Agent and LLM build that produced the output").
- **App now:** not recorded. The front end has no model.
- **Suggested fix:** keep it, and note that it comes from the agent service when one exists.

### 15. Wazuh enforces expiry too
- **PDF:** page 10 says `block_ip` uses Wazuh's firewall-drop response with a timeout equal to the approved duration, "so expiry is enforced by Wazuh as well as by AthenaSec".
- **App now:** not modelled. The app enforces expiry itself.
- **Suggested fix:** say which one wins if they disagree, and what the audit log records when Wazuh's timeout and the app's expiry differ.

### 16. No audit event for using an approval token
- **PDF:** page 8 lists seven event types (`recommendation_created`, `decision_recorded`, `action_executed`, `action_failed`, `action_expired`, `approval_timed_out`, `policy_violation_blocked`). The policy also requires every Tier 2 action to run only on a valid, unexpired, single-use token (pages 1 and 8), but nothing records the moment the token is used up.
- **App now:** writes a "Used approval token" event when the executor starts. It has no PDF event type, so it shows without one. The audit trail therefore reads created, decided, token used, executed, expired, and the token step has no PDF name.
- **Suggested fix:** add a `token_used` event type (with the token id and the recommendation it was bound to), or say that `action_executed` covers it and that the token is marked used at that point.

### 17. The PDF has no `kill_process`, `quarantine_file` or `reset_password`
- **PDF:** page 4 lists three Tier 2 actions (`block_ip`, `isolate_host`, `suspend_user_session`).
- **App now:** the Response Policies screen has room for the other response actions an EDR or directory would offer. The app lists these three as Tier 2 rows tagged Assumption: a SOC lead approves, 15 min to decide, no duration because they do not reverse on their own, never recommended by the agent. They start on neither list (denied); whitelisting one only makes it available, and it never becomes Automatic. `kill_process` is refused on a Critical host and `reset_password` on a privileged account, as the PDF's rules for critical systems and accounts require.
- **Suggested fix:** name the actions, their approver and limits, or say the list is closed to the three on page 4.

### 18. The PDF has no policy of its own beyond "a policy match is required"
- **PDF:** page 2 says a Tier 2 recommendation needs a matching policy. It does not say what a policy contains or what a person may change.
- **App now:** the policy is a whitelist (Automatic or Needs approval, with limits for Tier 2 actions), a blacklist (the six Tier 3 actions, locked) and protected targets (Never block, Never isolate; the PDF's entries locked). Anything not listed is denied. A person may only make a limit stricter (shorter, a higher approver, a higher minimum risk, within the PDF's caps: 24 h, 4 h, 15 min to decide, floors 70, 85, 75) and may not remove a Required entry.
- **Suggested fix:** state the model and what may and may not be changed: limits only down, floors only up, Tier 3 and the protected lists fixed.

### 19. "Needs approval" on a Tier 1 action has no meaning in the PDF
- **PDF:** a Tier 1 action runs without approval (page 3). Nothing describes a Tier 1 action that waits for a person.
- **App now:** the whitelist keeps a mode for every entry, but a Tier 1 action is locked to Automatic. Its "Needs approval" option is disabled ("Needs approval: available later") because the approval flow, tokens and executor are built around Tier 2 actions, and nothing in the app has an effect for a Tier 1 request to run. The engine would answer a Tier 1 action set to Needs approval with "needs approval" and the guard would not run it.
- **Suggested fix:** say whether a Tier 1 action may be held for approval and, if so, which uses (every use of nine actions on every alert would fill the queue).

## Values the catalogue had to assume

These are shown in the app with an "Assumption" tag. They are not gaps in the PDF's rules; they are columns the PDF does not fill.

- **What each Tier 2 action does** (`block_ip`, `isolate_host`, `suspend_user_session`): page 4 names them but gives no description. The wording is the app's. The three added rows (gap 17) are assumptions in what they do and in not reversing.
- **Isolation reverses at expiry:** see gap 6.
- **Which catalogue row each policy action runs:** no longer needed. The old IF/THEN policy actions (Create Case, Notify Administrator, Capture Telemetry, Record Response) are gone; the whitelist names catalogue actions directly (`create_ticket`, `notify_analyst`, `get_logs`), and Record Response is an audit write, not a permission.
