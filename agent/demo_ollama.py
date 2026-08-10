from langchain_ollama import ChatOllama


model = ChatOllama(
    model="qwen3:8b",
    base_url="http://localhost:11434",
)


response = model.invoke(
    """
    You are AthenaSec, a cybersecurity SOC assistant.

    Analyze this security event:

    148 failed SSH login attempts occurred against the root account
    from IP address 192.168.1.45 within five minutes.

    Briefly state:
    1. What likely happened
    2. How serious it is
    3. What an analyst should investigate next
    """
)

print(response.content)