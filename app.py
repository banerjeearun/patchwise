"""PatchWise: is this advisory really your problem, and what's the smallest upgrade that fixes it?

POST /chat keeps Project 1's shape: {message, session_id?} -> {response, session_id, tool_calls}.
Every tool call from every agent is in tool_calls, with an `agent` field
(lead, researcher:<package>, writer).
"""

import asyncio
import os
import uuid
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

load_dotenv(Path(__file__).parent / ".env")

from agent.team import answer_with_timeout  # noqa: E402
from tools.versions import store  # noqa: E402

HERE = Path(__file__).parent

# session_id -> messages since the last full answer. If PatchWise asked a clarifying question,
# the user's reply is combined with what they said before. In-memory, single process.
sessions: dict[str, list[str]] = {}

app = FastAPI()


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


class ChatResponse(BaseModel):
    response: str
    session_id: str
    tool_calls: list[dict]


@app.on_event("startup")
def warm() -> None:
    # Load the snapshot and embedding model before the first question, not during it.
    store()
    from tools.embed import embed_query
    embed_query("warm up")


@app.get("/")
def index():
    # no-cache: browsers otherwise keep serving an old page after a redeploy
    return FileResponse(HERE / "index.html", headers={"Cache-Control": "no-cache"})


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    session_id = request.session_id or str(uuid.uuid4())
    history = sessions.setdefault(session_id, [])
    history.append(request.message)
    message = request.message if len(history) == 1 else (
        "Earlier in this conversation the user said:\n" + "\n---\n".join(history[:-1])
        + f"\n\nYou asked a clarifying question. Their reply:\n{request.message}")
    try:
        result = await answer_with_timeout(message)
        response, tool_calls = result["response"], result["tool_calls"]
        if not result["clarify"]:
            sessions[session_id] = []  # answered: the next message starts fresh
    except asyncio.TimeoutError:
        response, tool_calls = ("This took longer than the time limit. Try fewer packages at once, "
                                "or one package and one advisory."), []
        sessions[session_id] = []
    except Exception as e:
        # Auth, quota, a model that won't stop: show it in the chat, not as a 500.
        response, tool_calls = f"Model call failed: {type(e).__name__}: {str(e)[:300]}", []
        sessions[session_id] = []
    return ChatResponse(response=response, session_id=session_id, tool_calls=tool_calls)


class TriageRequest(BaseModel):
    message: str


@app.post("/triage")
def triage_now(request: TriageRequest):
    """Code-only verdicts in well under a second, so the page can show the facts while the
    researchers work. Not part of the graded API; /chat is."""
    import time
    from agent.triage import triage
    from tools.versions import advisories_for
    t0 = time.perf_counter()
    out = triage(request.message)
    # The advisory records behind each count, so the page can show its work.
    for p in out["checked_pins"]:
        p["advisories"] = [{"id": a["id"], "aliases": a["aliases"], "summary": a["summary"],
                            "published": str(a["published"])[:10], "url": a["source_url"]}
                           for a in advisories_for(p["package"], p["pinned"])["advisories"]]
    s = store()
    out["provenance"] = {"ms": round((time.perf_counter() - t0) * 1000, 1),
                         "advisories": sum(len(v) for v in s.advisories.values()),
                         "releases": sum(len(v) for v in s.releases.values()) if hasattr(s, "releases") else None,
                         "snapshot": "2026-11-05"}
    return out


@app.post("/clear")
def clear(session_id: str | None = None):
    sessions.pop(session_id, None)
    return {"status": "ok"}


@app.get("/health")
def health():
    s = store()
    return {"status": "ok", "packages": list(s.packages),
            "advisories": sum(len(v) for v in s.advisories.values())}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
