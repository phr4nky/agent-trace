import { severityTag, statusTag } from './tags';

describe('tags', () => {
  it('maps severities and statuses to tag colours', () => {
    expect(severityTag('critical')).toBe('danger');
    expect(severityTag('high')).toBe('danger');
    expect(severityTag('medium')).toBe('warn');
    expect(severityTag('low')).toBe('info');
    expect(severityTag('info')).toBe('secondary');
    expect(severityTag(null)).toBe('success');
    expect(severityTag('unknown' as never)).toBe('secondary');
    expect(statusTag('completed')).toBe('success');
    expect(statusTag('running')).toBe('info');
    expect(statusTag('aborted')).toBe('warn');
  });
});
