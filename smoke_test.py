"""End-to-end test: connect to the bugbounty server over stdio with the official MCP client."""
import asyncio, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = r"C:\Users\LT\Desktop\Workspace\bugbounty-mcp\server.py"
PY = r"C:\Users\LT\Desktop\Workspace\bugbounty-mcp\.venv\Scripts\python.exe"


async def main():
    params = StdioServerParameters(command=PY, args=[SERVER], env=None)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print("TOOLS:", ", ".join(names))
            if "bb_resolve" in names:
                res = await session.call_tool("bb_resolve", {"host": "example.com"})
                print("bb_resolve output:")
                for c in res.content:
                    print("  ", c.text)


asyncio.run(main())
