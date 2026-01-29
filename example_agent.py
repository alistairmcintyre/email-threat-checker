"""
Example Strands Agent with Claude Integration

This example demonstrates how to create a Strands agent using Claude (Anthropic)
as the model provider.

Usage:
    export ANTHROPIC_API_KEY="your-api-key"
    uv run python example_agent.py
"""

import os
from strands import Agent
from strands.models.anthropic import AnthropicModel
from strands_tools import calculator, current_time


def create_agent() -> Agent:
    """Create a Strands agent with Claude as the model provider."""
    model = AnthropicModel(
        client_args={
            "api_key": os.environ.get("ANTHROPIC_API_KEY"),
        },
        max_tokens=1024,
        model_id="claude-sonnet-4-20250514",
        params={
            "temperature": 0.7,
        },
    )

    agent = Agent(
        model=model,
        tools=[calculator, current_time],
        system_prompt="You are a helpful assistant that can perform calculations and tell the time.",
    )

    return agent


def main():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY environment variable not set")
        print("Set it with: export ANTHROPIC_API_KEY='your-api-key'")
        return

    agent = create_agent()

    print("Strands Agent with Claude initialized!")
    print("Type 'quit' to exit.\n")

    while True:
        user_input = input("You: ").strip()
        if user_input.lower() in ("quit", "exit", "q"):
            print("Goodbye!")
            break
        if not user_input:
            continue

        response = agent(user_input)
        print(f"Agent: {response}\n")


if __name__ == "__main__":
    main()
