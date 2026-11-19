"""Text helpers for the approved knowledge base.

One tokenizer is used to index chunks and to read questions, in memory and in PostgreSQL, so
both stores behave the same way and a test on one holds for the other.
"""

import re
import unicodedata
from dataclasses import dataclass

MAX_DOCUMENT_CHARS = 200_000
MAX_CHUNK_CHARS = 1200

STOPWORDS = frozenset("""
a about above after again all also am an and any are as at be been being but by can could did do
does doing done down for from had has have having he her here hers him his how i if in into is it
its just me more most my no nor not of off on once only or other our ours out over own same she
should so some such than that the their theirs them then there these they this those through to
too under until up very was we were what when where which while who whom why will with would you
your yours
already also even ever yet
dont doesnt didnt isnt arent wasnt werent cant couldnt wont wouldnt shouldnt im ive youre
""".split())

# Irregular forms and one domain alias; everything else is handled by suffix rules
IRREGULAR = {"ran": "run", "admin": "administrator"}

_TOKEN = re.compile(r"[a-z0-9]+")
_HTML_BLOCK = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_HTML_TAG = re.compile(r"</?[A-Za-z][^>]*>")
_HEADING = re.compile(r"^(#{1,4})\s+(.*\S)\s*$")

_INJECTION = [
    (re.compile(r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier|all)\b.{0,30}"
                r"\b(instruction|rule|prompt|polic)", re.IGNORECASE | re.DOTALL),
     "tries to override earlier instructions"),
    (re.compile(r"\b(ignore|disregard)\b.{0,20}\b(the )?(above|previous)\b", re.IGNORECASE),
     "tries to override earlier instructions"),
    (re.compile(r"\byou are now\b", re.IGNORECASE), "tries to change the assistant's role"),
    (re.compile(r"\b(system|developer) prompt\b", re.IGNORECASE), "refers to the system prompt"),
    (re.compile(r"\b(execute|run|call|invoke)\b.{0,40}\b(cortex|shell|command|script)\b",
                re.IGNORECASE), "asks the assistant to run something"),
    (re.compile(r"\bBEGIN\s+(SYSTEM|INSTRUCTIONS?)\b", re.IGNORECASE), "fakes an instruction block"),
    (re.compile(r"\breveal\b.{0,30}\b(secret|password|key|token)\b", re.IGNORECASE),
     "asks for secrets"),
]


@dataclass(frozen=True)
class Chunk:
    heading: str
    text: str


def _undouble(word: str) -> str:
    """runn -> run, stopp -> stop; but not pass, miss, buzz."""
    if len(word) > 3 and word[-1] == word[-2] and word[-1] not in "lsz":
        return word[:-1]

    return word


def _stem(word: str) -> str:
    if len(word) > 6 and word.endswith("al"):  # approval -> approv, like approve and approved
        word = word[:-2]
    elif len(word) > 4 and word.endswith("ies"):
        word = word[:-3] + "y"
    elif len(word) > 5 and word.endswith("ing"):
        word = _undouble(word[:-3])
    elif len(word) > 4 and word.endswith("ed"):
        word = _undouble(word[:-2])
    elif len(word) > 2 and word.endswith("s") and not word.endswith("ss"):
        word = word[:-1]

    # approve / approved / approves meet at the same stem
    if len(word) > 4 and word.endswith("e"):
        word = word[:-1]

    return IRREGULAR.get(word, word)


def terms(text: str) -> list[str]:
    found = []

    for token in _TOKEN.findall(text.lower().replace("'", "").replace("\u2019", "")):
        if token in STOPWORDS or (len(token) == 1 and token.isalpha()):
            continue

        found.append(_stem(token))

    return found


def normalize(markdown: str) -> str:
    """Remove active content and invisible characters; keep the Markdown structure."""
    text = unicodedata.normalize("NFKC", markdown)
    text = _HTML_COMMENT.sub("", text)
    text = _HTML_BLOCK.sub("", text)
    text = _HTML_TAG.sub("", text)
    text = "".join(
        ch for ch in text
        if ch in "\n\t" or (unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn"))
    )
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()

    if not text:
        raise ValueError("The document is empty.")

    if len(text) > MAX_DOCUMENT_CHARS:
        raise ValueError("The document is too large.")

    return text


def injection_reason(text: str) -> str | None:
    for pattern, reason in _INJECTION:
        if pattern.search(text):
            return reason

    return None


def _split(text: str, max_chars: int) -> list[str]:
    parts, current = [], ""

    for paragraph in re.split(r"\n\s*\n", text):
        paragraph = paragraph.strip()

        while len(paragraph) > max_chars:  # one paragraph larger than a chunk
            if current:
                parts.append(current)
                current = ""
            parts.append(paragraph[:max_chars])
            paragraph = paragraph[max_chars:]

        if not paragraph:
            continue

        if current and len(current) + 2 + len(paragraph) > max_chars:
            parts.append(current)
            current = paragraph
        else:
            current = f"{current}\n\n{paragraph}" if current else paragraph

    if current:
        parts.append(current)

    return parts


def chunk(markdown: str, max_chars: int = MAX_CHUNK_CHARS) -> list[Chunk]:
    sections: list[tuple[str, list[str]]] = [("", [])]

    for line in markdown.splitlines():
        match = _HEADING.match(line)

        if match:
            sections.append((match.group(2).strip(), []))
        else:
            sections[-1][1].append(line)

    chunks = []

    for heading, lines in sections:
        body = "\n".join(lines).strip()

        for piece in _split(body, max_chars):
            chunks.append(Chunk(heading=heading, text=piece))

    return chunks
