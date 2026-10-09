"""Web search tool for open-source intelligence (OSINT) pivoting.

Wraps the keyless DuckDuckGo search backend to let Threavix pull the latest
public context about an indicator, campaign, vulnerability or threat actor.
"""

from langchain_community.tools import DuckDuckGoSearchResults

web_search_tool = DuckDuckGoSearchResults(num_results=10, handle_tool_error=True)
