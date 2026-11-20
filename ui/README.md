# agent-trace web UI

Angular 22 + [SwipyUI](https://www.npmjs.com/package/@swipergy/swipyui). It shows the traces that
recorders send to `agent-trace-server`: choose a source, pick a trace, and its causal graph opens
next to the list (the graph page of `agent-trace graph`, served by the server and shown in a
sandboxed frame). See [docs/server.md](../docs/server.md).

```sh
npm ci
npm start          # ng serve on http://localhost:4200, /api proxied to http://127.0.0.1:8080
npm test           # unit tests (Vitest)
npm run build      # dist/agent-trace-ui/browser, served by agent-trace-server --ui-dir
```

Everything shown comes from recorded agent sessions and may be written by an attacker: the UI
renders it as text only (Angular bindings, no `innerHTML`), the graph runs in a frame without
access to the app, and the server sends a strict Content-Security-Policy.
