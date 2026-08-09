from langchain_ollama import ChatOllama

model = ChatOllama(
    model="llama3.2:3b",
    base_url="http://127.0.0.1:11434",
)

response = model.invoke("Say hello.")

print(response.content)
