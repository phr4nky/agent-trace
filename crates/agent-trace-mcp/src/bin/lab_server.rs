//! Standalone local lab MCP server: `agent-trace-lab-server --documents <dir>`.

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut documents = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--documents" => documents = args.next(),
            "-h" | "--help" => {
                eprintln!("usage: agent-trace-lab-server --documents <fixture-dir>");
                return Ok(());
            }
            other => anyhow::bail!("unknown argument {other:?}"),
        }
    }
    let documents = documents.ok_or_else(|| anyhow::anyhow!("--documents <dir> is required"))?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(agent_trace_mcp::serve_stdio(documents))
}
