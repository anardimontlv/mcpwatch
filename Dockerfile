# The mcpwatch MCP server over stdio (used by directories such as Glama to inspect its tools). No dependencies beyond Python.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY mcpwatch ./mcpwatch
RUN pip install --no-cache-dir . && useradd -m mcp
USER mcp
ENTRYPOINT ["python", "-m", "mcpwatch.mcp_server"]
