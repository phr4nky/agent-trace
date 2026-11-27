import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  linkedSignal,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { Button } from '@swipergy/swipyui/button';
import { Card } from '@swipergy/swipyui/card';
import { EmptyState } from '@swipergy/swipyui/emptystate';
import { Message } from '@swipergy/swipyui/message';
import { Select, SelectOption } from '@swipergy/swipyui/select';
import { Column, Table } from '@swipergy/swipyui/table';
import { Tag } from '@swipergy/swipyui/tag';
import { Toolbar } from '@swipergy/swipyui/toolbar';

import { sourcesResource, tracesResource } from './api';
import { graphPath } from './helpers/graph';
import { lastValue } from './helpers/last-value';
import { severityTag, statusTag } from './helpers/tags';
import { SourceSummary, TraceRow } from './models';

/** How often sources and traces are reloaded (live view of running sessions). */
const REFRESH_MS = 4000;

@Component({
  selector: 'app-root',
  imports: [DatePipe, Button, Card, EmptyState, Message, Select, Table, Column, Tag, Toolbar],
  templateUrl: './app.html',
  styleUrl: './app.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class App {
  private readonly sanitizer = inject(DomSanitizer);

  /** A source named in the address (`?source=laptop`) is chosen when the current one is gone. */
  private readonly wantedSource = new URLSearchParams(window.location.search).get('source');

  private readonly sourcesRequest = sourcesResource();
  protected readonly sources = lastValue<SourceSummary[]>(this.sourcesRequest, []);

  /** The chosen source: kept while it exists, else the one in the address, else the first. */
  protected readonly sourceId = linkedSignal<SourceSummary[], string | null>({
    source: this.sources,
    computation: (sources, previous) => {
      const current = previous?.value;
      if (current && sources.some((s) => s.source_id === current)) {
        return current;
      }
      const wanted = sources.find((s) => s.name === this.wantedSource);
      return (wanted ?? sources[0])?.source_id ?? null;
    },
  });

  private readonly tracesRequest = tracesResource(this.sourceId);
  protected readonly traces = lastValue<TraceRow[]>(this.tracesRequest, [], this.sourceId);

  /** The chosen trace: kept while it exists, else the newest. */
  protected readonly selectedId = linkedSignal<TraceRow[], string | null>({
    source: this.traces,
    computation: (traces, previous) => {
      const current = previous?.value;
      return current && traces.some((t) => t.trace_id === current)
        ? current
        : (traces[0]?.trace_id ?? null);
    },
  });

  /** The table spins only when a source's traces are fetched first, not on every refresh. */
  protected readonly loading = computed(() => this.tracesRequest.status() === 'loading');
  protected readonly error = computed(() => {
    if (this.sourcesRequest.error()) {
      return 'Cannot reach agent-trace-server.';
    }
    return this.tracesRequest.error() ? 'Cannot load the traces of this source.' : null;
  });

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
  private readonly graphAddress = computed<string | null>(() => {
    const trace = this.selected();
    return trace ? graphPath(trace) : null;
  });
  protected readonly graphUrl = computed<SafeResourceUrl | null>(() => {
    const path = this.graphAddress();
    // Built from a checked trace ID on our own origin; the page runs in a sandboxed frame.
    return path ? this.sanitizer.bypassSecurityTrustResourceUrl(path) : null;
  });

  constructor() {
    // Keep the address in step, so a view can be linked (`?source=NAME`).
    effect(() => {
      const name = this.source()?.name;
      if (name) {
        window.history.replaceState(null, '', `?source=${encodeURIComponent(name)}`);
      }
    });
    const timer = setInterval(() => this.refresh(), REFRESH_MS);
    inject(DestroyRef).onDestroy(() => clearInterval(timer));
  }

  protected refresh(): void {
    this.sourcesRequest.reload();
    this.tracesRequest.reload();
  }

  protected selectSource(value: unknown): void {
    this.sourceId.set(typeof value === 'string' ? value : null);
  }

  protected select(selection: TraceRow | TraceRow[] | null): void {
    const row = Array.isArray(selection) ? selection[0] : selection;
    this.selectedId.set(row?.trace_id ?? null);
  }
}
