import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { Button } from '@swipergy/swipyui/button';
import { Card } from '@swipergy/swipyui/card';
import { EmptyState } from '@swipergy/swipyui/emptystate';
import { Message } from '@swipergy/swipyui/message';
import { Select, SelectOption } from '@swipergy/swipyui/select';
import { Column, Table } from '@swipergy/swipyui/table';
import { Tag, TagSeverity } from '@swipergy/swipyui/tag';
import { Toolbar } from '@swipergy/swipyui/toolbar';

import { SourceSummary, TraceApi, TraceRow } from './api';

/** How often sources and traces are reloaded (live view of running sessions). */
const REFRESH_MS = 4000;

/** Tag colour of a finding severity (no finding: clean). */
export function severityTag(severity: string | null): TagSeverity {
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
    default:
      return 'success';
  }
}

/** Tag colour of a trace status. */
export function statusTag(status: string): TagSeverity {
  switch (status) {
    case 'completed':
      return 'success';
    case 'running':
      return 'info';
    default:
      return 'warn';
  }
}

@Component({
  selector: 'app-root',
  imports: [DatePipe, Button, Card, EmptyState, Message, Select, Table, Column, Tag, Toolbar],
  templateUrl: './app.html',
  styleUrl: './app.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class App {
  private readonly api = inject(TraceApi);
  private readonly sanitizer = inject(DomSanitizer);

  protected readonly sources = signal<SourceSummary[]>([]);
  protected readonly sourceId = signal<string | null>(null);
  protected readonly traces = signal<TraceRow[]>([]);
  protected readonly selectedId = signal<string | null>(null);
  protected readonly loading = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly severityTag = severityTag;
  protected readonly statusTag = statusTag;

  protected readonly sourceOptions = computed<SelectOption<string>[]>(() =>
    this.sources().map((s) => ({ label: `${s.name} (${s.traces})`, value: s.source_id })),
  );
  protected readonly source = computed(
    () => this.sources().find((s) => s.source_id === this.sourceId()) ?? null,
  );
  protected readonly selected = computed(
    () => this.traces().find((t) => t.trace_id === this.selectedId()) ?? null,
  );
  /**
   * Address of the graph frame as a plain string: the periodic refresh replaces every trace
   * object, but an unchanged string stops the signal here, so the frame is not reloaded (and
   * the node the user picked in the graph stays selected).
   */
  private readonly graphPath = computed<string | null>(() => {
    const trace = this.selected();
    return trace ? this.api.graphPath(trace) : null;
  });
  protected readonly graphUrl = computed<SafeResourceUrl | null>(() => {
    const path = this.graphPath();
    // Built from a checked trace ID on our own origin; the page runs in a sandboxed frame.
    return path ? this.sanitizer.bypassSecurityTrustResourceUrl(path) : null;
  });

  /** A source named in the address (`?source=laptop`) is chosen first. */
  private wantedSource: string | null = new URLSearchParams(window.location.search).get('source');

  constructor() {
    this.refresh();
    const timer = setInterval(() => this.refresh(), REFRESH_MS);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
  }

  protected refresh(): void {
    this.api.sources().subscribe({
      next: (sources) => {
        this.error.set(null);
        this.sources.set(sources);
        const current = this.sourceId();
        if (!current || !sources.some((s) => s.source_id === current)) {
          const wanted = sources.find((s) => s.name === this.wantedSource);
          this.wantedSource = null;
          this.selectSource((wanted ?? sources[0])?.source_id ?? null);
        } else {
          this.loadTraces(current, false);
        }
      },
      error: () => this.error.set('Cannot reach agent-trace-server.'),
    });
  }

  protected selectSource(value: unknown): void {
    const id = typeof value === 'string' ? value : null;
    this.sourceId.set(id);
    // Keep the address in step, so a view can be linked (`?source=NAME`).
    const name = this.sources().find((s) => s.source_id === id)?.name;
    if (name) {
      window.history.replaceState(null, '', `?source=${encodeURIComponent(name)}`);
    }
    this.selectedId.set(null);
    this.traces.set([]);
    if (id) {
      this.loadTraces(id, true);
    }
  }

  protected select(selection: TraceRow | TraceRow[] | null): void {
    const row = Array.isArray(selection) ? selection[0] : selection;
    this.selectedId.set(row?.trace_id ?? null);
  }

  private loadTraces(sourceId: string, showLoading: boolean): void {
    if (showLoading) {
      this.loading.set(true);
    }
    this.api.traces(sourceId).subscribe({
      next: (traces) => {
        if (this.sourceId() !== sourceId) {
          return;
        }
        this.traces.set(traces);
        this.loading.set(false);
        // Show the newest trace until the user picks one.
        if (!this.selected() && traces.length > 0) {
          this.selectedId.set(traces[0].trace_id);
        }
      },
      error: () => {
        this.loading.set(false);
        this.error.set('Cannot load the traces of this source.');
      },
    });
  }
}
