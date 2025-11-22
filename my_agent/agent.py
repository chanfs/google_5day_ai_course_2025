# agent.py

from .whois import get_whois_info
from .nmap import nmap_scan
import re
import sys
import asyncio
import os
from dotenv import load_dotenv
from google.adk.agents.llm_agent import Agent
from google.adk.agents.sequential_agent import SequentialAgent
from google.adk.tools import FunctionTool
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.genai.types import Content, Part

load_dotenv()

def extract_ip_range(whois_output: str) -> str:
    """
    Extracts the IP range from the output of the whois command.
    This is a simple example and might need to be adjusted for different whois outputs.
    """
    # The whois output is a dictionary, so we need to get the 'output' key
    if isinstance(whois_output, dict) and "output" in whois_output:
        whois_output = whois_output["output"]

    match = re.search(r'CIDR:\s*([0-9./]+)', whois_output)
    if match:
        return match.group(1)
    return ""

whois_tool = FunctionTool(get_whois_info)
nmap_tool = FunctionTool(nmap_scan)

def create_sequential_agent():
    # Step 1: Define the whois agent
    whois_agent = Agent(
        model='gemini-2.5-flash-lite',
        name='whois_agent',
        description='Retrieves WHOIS information for a domain.',
        instruction='You are a WHOIS specialist. Given a domain, return the full WHOIS record.',
        tools=[whois_tool],
        output_key='whois_record'
    )

    # Step 2: Define the nmap agent
    nmap_agent = Agent(
        model='gemini-2.5-flash-lite',
        name='nmap_agent',
        description='Scans an IP range with nmap.',
        instruction='You are an Nmap specialist. Given an IP range from the whois record, perform a ping scan. The whois record is: {whois_record}',
        tools=[nmap_tool]
    )

    # Step 3: Create the SequentialAgent
    sequential_agent = SequentialAgent(
        name='domain_to_nmap_agent',
        sub_agents=[whois_agent, nmap_agent]
    )
    return sequential_agent

root_agent = create_sequential_agent()

async def main():
    if len(sys.argv) < 2:
        print("Usage: python -m my_agent.agent <domain_name>")
        sys.exit(1)

    domain_name = sys.argv[1]

    # Create a session service
    session_service = InMemorySessionService()
    await session_service.create_session(app_name="my_agent", user_id="user1", session_id="session1")

    # Create a runner
    runner = Runner(
        agent=root_agent,
        app_name="my_agent",
        session_service=session_service,
    )

    # Create a message
    new_message = Content(parts=[Part(text=domain_name)])

    # Run the agent
    final_response = None
    async for response in runner.run_async(user_id="user1", session_id="session1", new_message=new_message):
        final_response = response

    # Print the final output
    if final_response:
        print(final_response["output"])

if __name__ == "__main__":
    asyncio.run(main())
