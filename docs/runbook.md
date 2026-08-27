# Incident Response Runbook

This is the procedural detail behind the [Incident Response Walkthrough](../README.md#incident-response-walkthrough) in the README. Like the rest of this repository, it's a design and documentation artifact: it was written and reasoned through in detail, but it hasn't been exercised against a live AWS account or a live incident.

There are two independent paths here, matching the two flows in [`architecture/incident-response-flow.png`](../architecture/incident-response-flow.png). One is driven by GuardDuty, for threat findings. The other is driven by Config, for compliance drift. They never cross: a GuardDuty finding doesn't route through Config's loop, and a Config non-compliance doesn't route through Security Hub, EventBridge, or Lambda.

## Incident Type

The GuardDuty path covers any finding that reaches Security Hub with severity 7 or higher, regardless of category. Three categories are called out explicitly in this project's scope:

- **CryptoCurrency**, crypto-mining activity on a compute resource. This is the worked example used throughout the README and the diagram.
- **Recon**, reconnaissance style API activity (port scanning, unusual enumeration calls) suggesting a principal or instance is being cased for a further attack.
- **Backdoor**, indicators that a compromised resource is being used for outbound attack activity, for example contacting a known command and control host.

All three normalize into the same ASFF finding shape in Security Hub and go through the same automated path below. The finding type changes the human investigation in Step 3 of Human Escalation, not the automated steps that come before it.

The Config path covers any resource Config evaluates as non-compliant against one of the four managed rules in scope (`rds-storage-encrypted`, `encrypted-volumes`, `s3-bucket-public-read-prohibited`, `iam-user-mfa-enabled`). This is configuration drift, not an active threat.

## Detection

GuardDuty path:
1. GuardDuty's account wide detector flags anomalous activity and publishes a finding.
2. Security Hub ingests the finding and normalizes it into ASFF (AWS Security Finding Format), which is what lets one EventBridge rule handle findings from every enabled Security Hub source the same way.
3. An EventBridge rule matching on severity 7 or higher picks up the normalized finding and invokes the incident response Lambda. Findings below that threshold stay visible in Security Hub for manual triage but don't trigger automation. The threshold exists so a low confidence or informational finding doesn't page anyone or trigger containment on what turns out to be a false positive.

Config path:
1. Config continuously evaluates in scope resources against its managed rules. This isn't a point in time check, so a resource that was compliant at creation and drifted six weeks later still gets caught.
2. A resource evaluated as non-compliant triggers an SSM Automation document directly. There's no EventBridge or Lambda hop in this path, and no severity threshold: every non-compliant evaluation triggers remediation.

## Automated Response

On the GuardDuty path, the Lambda handles containment and notification in parallel, not one after the other:
- **Containment.** Quarantine the resource's security group by replacing its rules with a deny all, no egress group, take a forensic snapshot of the affected volume or volumes, and tag the resource (for example `incident-status=quarantined`, `finding-id=<id>`) so it's obvious in the console that this resource is mid investigation and shouldn't be treated as healthy inventory.
- **Notification.** Publish to an SNS topic that fans out to on call paging and a Slack channel, carrying the finding type, severity, resource ID, and a link to the Security Hub finding.

On the Config path, the SSM Automation document remediates the specific drift directly, for example re-enabling the S3 bucket's public access block, or turning on encryption for a flagged resource where the resource type allows in-place remediation. No human facing notification fires on this path. The remediation itself is the response, and Config's own compliance dashboard reflects the after state.

## Human Escalation

Automation buys time and preserves evidence, but it doesn't replace investigation. Once the on call responder gets the SNS alert:

1. **Acknowledge** the page and open the linked Security Hub finding to confirm it isn't a known false positive that's already been suppressed elsewhere.
2. **Confirm containment took effect.** Check the resource's tags and security group against what the Lambda should have applied. If containment didn't apply cleanly, for example because the Lambda's own execution role was missing a permission it needed, escalate to manual containment right away rather than assuming the automation succeeded.
3. **Investigate root cause**, guided by finding type:
   - *CryptoCurrency*: review the resource's process and network activity through its logs, and confirm whether the entry point was a vulnerable application dependency, an exposed credential, or a misconfigured security group.
   - *Recon*: identify the source, whether that's an external IP or an internal principal that may itself be compromised, and check CloudTrail for what that principal or IP attempted before and after the flagged activity.
   - *Backdoor*: treat the resource as compromised, not just suspicious. Prioritize confirming what other resources it had credentials or network access to, since the containment snapshot exists specifically to support this without needing to un-quarantine the live resource.
4. **Decide on further action.** Restore from a known good state, terminate and replace the resource from the Auto Scaling Group's launch template, or extend containment to related resources if the investigation shows lateral movement.
5. **Close out** the Security Hub finding with a disposition (true positive and remediated, false positive, or benign) so it stops appearing in the active queue, and record the incident for the post incident review.

On the Config path, human involvement is asynchronous rather than page driven. Since remediation already happened automatically, the expectation is a periodic review of the Config compliance dashboard, not a real time page, to confirm remediations are landing correctly and to look into why a resource drifted in the first place. The runbook closes out the individual instance, but repeated drift on the same rule is a sign the underlying deployment process needs a fix, not just another round of auto-remediation.
