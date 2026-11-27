import { TRACE } from '../testing/fixtures';
import { graphPath, isTraceId } from './graph';

describe('graph addresses', () => {
  it('accepts only well-formed trace IDs for frame addresses', () => {
    expect(isTraceId(TRACE.trace_id)).toBe(true);
    for (const bad of ['', 'x', '../../etc', `${TRACE.trace_id}/../x`, 'javascript:alert(1)']) {
      expect(isTraceId(bad)).toBe(false);
    }
  });

  it('builds graph addresses only from well-formed trace IDs', () => {
    expect(graphPath(TRACE)).toBe(`/api/v1/traces/${TRACE.trace_id}/graph?v=13`);
    expect(graphPath({ ...TRACE, trace_id: '../../etc' })).toBeNull();
  });
});
