import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { App } from './app';
import { SOURCE, TRACE } from './testing/fixtures';
import { SourceSummary, TraceRow } from './models';

describe('App', () => {
  let http: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    http.verify();
    window.history.replaceState(null, '', '/');
  });

  /** Let the resources send their requests, then answer the one for `url` (and `source`). */
  async function answer(
    url: string,
    body: object | null,
    source?: string,
    error = false,
  ): Promise<void> {
    await settle();
    const req = http.expectOne(
      (r) => r.url === url && (source === undefined || r.params.get('source') === source),
    );
    if (error) {
      req.flush('down', { status: 502, statusText: 'Bad Gateway' });
    } else {
      req.flush(body);
    }
    await settle();
  }

  /**
   * Let answered responses reach the resources (they are delivered asynchronously), then run
   * effects and change detection, so the next requests are sent and the view is current.
   */
  async function settle(): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve));
    TestBed.tick();
  }

  function frameSrc(page: HTMLElement): string | null {
    return page.querySelector('iframe.graph')?.getAttribute('src') ?? null;
  }

  it('loads the sources, picks the first, lists its traces and shows the newest graph', async () => {
    const fixture = TestBed.createComponent(App);
    await answer('/api/v1/sources', [SOURCE]);
    await answer('/api/v1/traces', [TRACE], SOURCE.source_id);
    await fixture.whenStable();
    const page: HTMLElement = fixture.nativeElement;
    expect(page.textContent).toContain('agent-trace');
    expect(page.textContent).toContain('local-lab/exfil-attempt');
    const frame = page.querySelector('iframe.graph') as HTMLIFrameElement;
    expect(frame).toBeTruthy();
    expect(frame.getAttribute('sandbox')).toBe('allow-scripts');
    expect(frameSrc(page)).toBe(`/api/v1/traces/${TRACE.trace_id}/graph?v=13`);
    expect(window.location.search).toBe('?source=laptop');
    fixture.destroy();
  });

  it('chooses the source named in the address', async () => {
    window.history.replaceState(null, '', '?source=ci-runner');
    const fixture = TestBed.createComponent(App);
    const ci: SourceSummary = {
      ...SOURCE,
      source_id: '5a0c2d9e-1b3f-4e6a-8c7d-9e0f1a2b3c4d',
      name: 'ci-runner',
    };
    await answer('/api/v1/sources', [SOURCE, ci]);
    await answer('/api/v1/traces', [], ci.source_id);
    await fixture.whenStable();
    expect(window.location.search).toBe('?source=ci-runner');
    fixture.destroy();
  });

  it('says so when the server cannot be reached', async () => {
    const fixture = TestBed.createComponent(App);
    await answer('/api/v1/sources', null, undefined, true);
    await fixture.whenStable();
    expect(fixture.nativeElement.textContent).toContain('Cannot reach agent-trace-server.');
    fixture.destroy();
  });

  it('keeps the traces on screen when a refresh fails, and drops the error once it works again', async () => {
    const fixture = TestBed.createComponent(App);
    await answer('/api/v1/sources', [SOURCE]);
    await answer('/api/v1/traces', [TRACE], SOURCE.source_id);
    await fixture.whenStable();

    const view = fixture.componentInstance as unknown as { refresh(): void };
    view.refresh();
    await answer('/api/v1/sources', null, undefined, true);
    await answer('/api/v1/traces', null, SOURCE.source_id, true);
    await fixture.whenStable();
    const page: HTMLElement = fixture.nativeElement;
    expect(page.textContent).toContain('Cannot reach agent-trace-server.');
    expect(page.textContent).toContain('local-lab/exfil-attempt');
    expect(frameSrc(page)).toBe(`/api/v1/traces/${TRACE.trace_id}/graph?v=13`);

    view.refresh();
    await answer('/api/v1/sources', [SOURCE]);
    await answer('/api/v1/traces', [{ ...TRACE, events: 14 }], SOURCE.source_id);
    await fixture.whenStable();
    expect(page.textContent).not.toContain('Cannot reach agent-trace-server.');
    expect(frameSrc(page)).toBe(`/api/v1/traces/${TRACE.trace_id}/graph?v=14`);
    fixture.destroy();
  });

  it('starts empty for a newly chosen source and selects its newest trace', async () => {
    const fixture = TestBed.createComponent(App);
    const ci: SourceSummary = {
      ...SOURCE,
      source_id: '5a0c2d9e-1b3f-4e6a-8c7d-9e0f1a2b3c4d',
      name: 'ci-runner',
    };
    const ciTrace: TraceRow = {
      ...TRACE,
      trace_id: '7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f',
      name: 'ci/nightly',
    };
    await answer('/api/v1/sources', [SOURCE, ci]);
    await answer('/api/v1/traces', [TRACE], SOURCE.source_id);
    await fixture.whenStable();

    const view = fixture.componentInstance as unknown as { selectSource(id: unknown): void };
    view.selectSource(ci.source_id);
    await settle(); // its traces are still on the way
    const page: HTMLElement = fixture.nativeElement;
    expect(page.textContent).not.toContain('local-lab/exfil-attempt');
    expect(frameSrc(page)).toBeNull();

    await answer('/api/v1/traces', [ciTrace], ci.source_id);
    await fixture.whenStable();
    expect(page.textContent).toContain('ci/nightly');
    expect(frameSrc(page)).toBe(`/api/v1/traces/${ciTrace.trace_id}/graph?v=13`);
    expect(window.location.search).toBe('?source=ci-runner');
    fixture.destroy();
  });
});
