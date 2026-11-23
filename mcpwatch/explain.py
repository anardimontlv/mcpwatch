"""Plain-language "why it matters / what to do" for each notable radar reason.

Written by us, never derived from third-party text, so it is safe on every surface: the radar page (injected as JSON),
digest emails, Slack, and the weekly article. Keys are notable_reasons() strings up to the first " (".
"""

EXPLAIN = {
    "endpoint stopped requiring credentials": {
        "why": "The endpoint now answers without credentials where it used to ask for them. Anyone who knows the URL can call "
               "its tools: if they read or change your data, strangers may be able to as well.",
        "do": "Ask the maintainer whether this was intended. Until you know, don't send it secrets or private data.",
    },
    "a newly added tool can execute commands or delete data": {
        "why": "Your agent can now be steered (by a prompt, a web page or a poisoned document) into running commands or deleting "
               "data through this server. A destructive capability that appears after you approved a server is the shape of a rug pull.",
        "do": "Review the new tool before your next session, keep per-call approval on for it, and re-lock (mcpwatch lock) only once you trust it.",
    },
    "grade dropped": {
        "why": "The server now trips a security check it passed before, so its risk went up.",
        "do": "Open the server page to see the new finding and decide whether it still fits your setup.",
    },
    "new tool text matches a tool-poisoning pattern": {
        "why": "A tool description now contains instructions aimed at the AI model rather than at you, such as telling it to "
               "ignore earlier rules or to read files. Agents treat tool descriptions as instructions, so this can hijack an agent "
               "without any visible prompt.",
        "do": "Treat it as a possible rug pull: disconnect the server and don't reconnect until a person has read the new tool text. "
              "mcpwatch check fails on it when the server is pinned.",
    },
    "new tool text contains invisible characters": {
        "why": "The tool text contains characters people can't see but models can read, a known way to hide instructions inside "
               "an innocent-looking description.",
        "do": "Treat it like tool poisoning: disconnect, and inspect the raw tool text before trusting the server again.",
    },
}


def explain(reason):
    """The explanation for a notable reason string, or None."""
    return EXPLAIN.get(str(reason).split(" (")[0])
