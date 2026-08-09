from typing import TypedDict

from langgraph.graph import StateGraph, START, END
from langchain_ollama import ChatOllama


class State(TypedDict):
    message: str
    response: str


model = ChatOllama(
    model="llama3.2:3b",
    base_url="http://127.0.0.1:11434",
)


def ask_model(state: State):
    result = model.invoke(state["message"])

    return {
        "response": result.content
    }


graph = StateGraph(State)

graph.add_node("ask_model", ask_model)

graph.add_edge(START, "ask_model")
graph.add_edge("ask_model", END)

app = graph.compile()


result = app.invoke({
    "message": "how is the wether in uae."
})

print(result["response"])
