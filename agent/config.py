"""Models and caps in one place. Swap models here, not in agent code."""

import os

from agents import ModelSettings
from agents.extensions.models.litellm_model import LitellmModel

LEAD_MODEL = os.environ.get("PATCHWISE_LEAD_MODEL", "vertex_ai/gemini-3.5-flash")
RESEARCHER_MODEL = os.environ.get("PATCHWISE_RESEARCHER_MODEL", "vertex_ai/gemini-3.5-flash")
WRITER_MODEL = os.environ.get("PATCHWISE_WRITER_MODEL", "vertex_ai/gemini-3.5-flash")


def model(name: str) -> LitellmModel:
    # api_key is unused: Vertex AI authenticates with gcloud / the Cloud Run service account.
    return LitellmModel(model=name, api_key="unused")


def settings(parallel: bool = False) -> ModelSettings:
    return ModelSettings(
        parallel_tool_calls=parallel or None,
        extra_args={"vertex_location": "global", "timeout": 90, "num_retries": 3},
    )


MAX_RESEARCHERS = 8         # researcher runs per request, across all rounds (code-enforced)
MAX_FOLLOWUP_ROUNDS = 2     # Lead may go back for gaps at most this many times
LEAD_MAX_TURNS = 6          # fan-out + 2 follow-ups + final answer, with slack
RESEARCHER_MAX_TURNS = 12
RESEARCHER_TOOL_BUDGET = 10  # code-enforced; tools return 'budget used up' after this
RESEARCHER_STAGGER_S = 1.5   # delay between researcher starts, to avoid a burst of requests
RESEARCHER_TIMEOUT_S = 110   # one researcher's wall-clock cap; then the code fallback takes over
WRITER_RESERVE_S = 60        # time kept free for the Lead's last turn and the Writer
FOLLOWUP_MIN_LEFT_S = 150    # the Lead may go back for gaps only with this much time left
REQUEST_TIMEOUT_S = 270     # graders wait up to 300 s
TOOL_RESULT_CHARS = 6000    # tool output kept in the /chat trace, per call
