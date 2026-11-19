# Risk scores, classifications and response policy

## Three different things
The detection model gives a classification and a confidence, for example brute_force at 90 percent. The risk engine gives a risk score from 0 to 100 and a band, calculated from recorded factors. The action policy decides what may be done about a proposed response. These are separate and one does not set another.

## Classification labels
The labels are benign, brute_force, privilege_escalation, privilege_misuse and unknown. The model's label and the written analysis can disagree; when they do, the disagreement is reported and the stored label is not overwritten.

## Policy outcomes
AUTO_ALLOWED means the policy allows the action to proceed, still subject to the runtime safeguards. APPROVAL_REQUIRED means an authorised person must approve the exact action. NOT_ALLOWED means the action is refused and an internal case is created.

## Reading a risk score
A high score means the recorded factors add up to high risk. It does not say an attack succeeded.
