import { TagSeverity } from '@swipergy/swipyui/tag';

import { Severity, TraceStatus } from '../models';

/** Tag colour of a finding severity (no finding: clean). */
export function severityTag(severity: Severity | null): TagSeverity {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'danger';
    case 'medium':
      return 'warn';
    case 'low':
      return 'info';
    case 'info':
      return 'secondary';
    case null:
      return 'success';
    default:
      // A severity this build does not know yet.
      return 'secondary';
  }
}

/** Tag colour of a trace status. */
export function statusTag(status: TraceStatus): TagSeverity {
  switch (status) {
    case 'completed':
      return 'success';
    case 'running':
      return 'info';
    case 'aborted':
    default:
      // Aborted, or a status this build does not know yet.
      return 'warn';
  }
}
