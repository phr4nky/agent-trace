import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { App, severityTag, statusTag } from './app';
import { isTraceId } from './api';

const SOURCE = {
  source_id: '0b8e7c1e-6f1d-4d6e-9a43-2a1c7f1b3c4d',
  name: 'laptop',
  created_at: '2026-11-20T10:00:00Z',
  last_seen_at: '2026-11-20T10:05:00Z',
  last_ip: '127.0.0.1',
  traces: 1,
};

const TRACE = {
  trace_id: '2fd80407-4c89-5f64-bc7e-93536e96e8ca',
  name: 'local-lab/exfil-attempt',
  status: 'completed',
  created_at: '2026-11-20T10:01:00Z',
  execution_mode: 'simulated',
  events: 13,
  findings: 4,
  max_severity: 'high',
};

describe('App', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();
  });

  it('loads the sources, picks the first, lists its traces and shows the newest graph', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/sources').flush([SOURCE]);
    http
      .expectOne((req) => req.url === '/api/v1/traces' && req.params.get('source') === SOURCE.source_id)
      .flush([TRACE]);
    await fixture.whenStable();
    const page: HTMLElement = fixture.nativeElement;
    expect(page.textContent).toContain('agent-trace');
    expect(page.textContent).toContain('local-lab/exfil-attempt');
    const frame = page.querySelector('iframe.graph') as HTMLIFrameElement;
    expect(frame).toBeTruthy();
    expect(frame.getAttribute('sandbox')).toBe('allow-scripts');
    expect(frame.getAttribute('src')).toBe(`/api/v1/traces/${TRACE.trace_id}/graph?v=13`);
    fixture.destroy();
  });

  it('chooses the source named in the address', async () => {
    window.history.replaceState(null, '', '?source=ci-runner');
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    const ci = { ...SOURCE, source_id: '5a0c2d9e-1b3f-4e6a-8c7d-9e0f1a2b3c4d', name: 'ci-runner' };
    http.expectOne('/api/v1/sources').flush([SOURCE, ci]);
    http.expectOne((req) => req.params.get('source') === ci.source_id).flush([]);
    await fixture.whenStable();
    expect(window.location.search).toBe('?source=ci-runner');
    window.history.replaceState(null, '', '/');
    fixture.destroy();
  });

  it('says so when the server cannot be reached', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/sources').flush('down', { status: 502, statusText: 'Bad Gateway' });
    await fixture.whenStable();
    expect(fixture.nativeElement.textContent).toContain('Cannot reach agent-trace-server.');
    fixture.destroy();
  });
});

describe('tags and IDs', () => {
  it('maps severities and statuses to tag colours', () => {
    expect(severityTag('critical')).toBe('danger');
    expect(severityTag('high')).toBe('danger');
    expect(severityTag('medium')).toBe('warn');
    expect(severityTag('low')).toBe('info');
    expect(severityTag(null)).toBe('success');
    expect(statusTag('completed')).toBe('success');
    expect(statusTag('running')).toBe('info');
    expect(statusTag('aborted')).toBe('warn');
  });

  it('accepts only well-formed trace IDs for frame addresses', () => {
    expect(isTraceId(TRACE.trace_id)).toBe(true);
    for (const bad of ['', 'x', '../../etc', `${TRACE.trace_id}/../x`, 'javascript:alert(1)']) {
      expect(isTraceId(bad)).toBe(false);
    }
  });
});
