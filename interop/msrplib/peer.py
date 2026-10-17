#!/usr/bin/env python3
# Copyright 2023 宋昊文
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The msrplib end of tests/msrp_interop.rs, see interop/README.md.
#
#   peer.py accept LOCAL_URI REMOTE_URI    waits for the connection
#   peer.py connect LOCAL_URI REMOTE_URI   opens it, binding with an empty SEND
#
# Either way it then sends the messages of MESSAGES, takes what the other end
# sends, and writes one JSON object per line on stdout: what it received, the
# responses and REPORTs it got, and every chunk that came in. It ends with
# {"event": "done"} once the other end's messages and the REPORTs it asked for
# are in, or after TIMEOUT seconds.

import hashlib
import json
import sys
import traceback

# the reactor runs in the main greenlet, msrplib in another: eventlib's own
# hub cannot take the main greenlet over with greenlet 3
from eventlib.twistedutil import join_reactor  # noqa: F401
from twisted.internet import reactor

from eventlib import api, proc
from msrplib import protocol
from msrplib.connect import DirectAcceptor, DirectConnector
from msrplib.session import GreenMSRPSession
from msrplib.trafficlog import Logger
from msrplib.transport import MSRPTransactionError

TIMEOUT = 30

ACCEPTED_TYPES = ['text/plain', 'application/octet-stream']

# label, size, content type, success report, failure report, chunk size
MESSAGES = [
    ('py-small', 5, 'text/plain', True, None, None),
    ('py-chunked', 25000, 'application/octet-stream', True, None, 10000),
    ('py-whole', 5000, 'application/octet-stream', False, None, None),
    ('py-no-response', 5, 'text/plain', False, 'no', None),
    ('py-rejected', 5, 'application/x-rejected', False, None, None),
]

# what the other end sends that is accepted
EXPECTED = 3


def out(**fields):
    print(json.dumps(fields), flush=True)


def body(label, size):
    seed = label.encode()
    return (seed * (size // len(seed) + 1))[:size]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class ChunkLogger(Logger):
    """Writes out every chunk that comes in."""

    def received_chunk(self, data, transport):
        out(event='chunk', transaction_id=data.transaction_id, method=data.method,
            code=data.code, message_id=str(data.headers['Message-ID'].decoded)
            if 'Message-ID' in data.headers else None,
            flag=data.contflag, size=data.size)


def send(session, label, size, content_type, success_report, failure_report, chunk_size):
    data = body(label, size)
    message_id = label
    chunk_size = chunk_size or size
    start = 1
    while True:
        part = data[start - 1:start - 1 + chunk_size]
        chunk = session.msrp.make_send_request(message_id=message_id, data=part, start=start,
                                               end=start + len(part) - 1, length=size)
        chunk.add_header(protocol.ContentTypeHeader(content_type))
        if success_report:
            chunk.add_header(protocol.SuccessReportHeader('yes'))
        if failure_report is not None:
            chunk.add_header(protocol.FailureReportHeader(failure_report))
        out(event='sent', label=label, transaction_id=chunk.transaction_id, flag=chunk.contflag,
            byte_range=chunk.headers['Byte-Range'].encoded)
        if failure_report == 'no':
            # nothing to wait for; deliver_chunk() fails on it in msrplib 0.21.3
            session.send_chunk(chunk)
            code = None
        else:
            try:
                code = session.deliver_chunk(chunk).code
            except MSRPTransactionError as e:
                code = e.code
        out(event='response', label=label, transaction_id=chunk.transaction_id, code=code)
        start += len(part)
        if start > size or code not in (200, None):
            break
    return message_id, sha256(data)


def main():
    mode, local_uri, remote_uri = sys.argv[1:4]
    local_uri = protocol.URI.parse(local_uri)
    remote_uri = protocol.URI.parse(remote_uri)
    logger = ChunkLogger()

    if mode == 'accept':
        connector = DirectAcceptor(logger=logger)
        connector.prepare(local_uri)
        out(event='listening', uri=str(local_uri))
    else:
        connector = DirectConnector(logger=logger)
        connector.prepare(local_uri)
    transport = connector.complete([remote_uri])
    out(event='connected')
    session = GreenMSRPSession(transport, accept_types=ACCEPTED_TYPES)

    incoming = {}  # Message-ID: (content type, data, flags)
    received = set()
    reported = {}  # Message-ID: [(status, byte range)]

    def reader():
        while True:
            chunk = session.receive_chunk()
            if chunk.method == 'SEND' and chunk.size > 0:
                message_id = str(chunk.message_id)
                content_type, data, flags = incoming.setdefault(message_id, (str(chunk.content_type), bytearray(), []))
                start = chunk.byte_range[0]
                data[start - 1:start - 1 + chunk.size] = chunk.data
                flags.append(chunk.contflag)
                total = chunk.byte_range[2]
                if chunk.contflag == '$' and len(data) == (total or len(data)):
                    received.add(message_id)
                    out(event='received', message_id=message_id, content_type=content_type,
                        size=len(data), sha256=sha256(bytes(data)), flags=''.join(flags))
            elif chunk.method == 'REPORT':
                status = chunk.status
                byte_range = chunk.headers['Byte-Range'].encoded if 'Byte-Range' in chunk.headers else None
                reported.setdefault(str(chunk.message_id), []).append((status.code, byte_range))
                out(event='report', message_id=str(chunk.message_id), code=status.code,
                    comment=status.comment, byte_range=byte_range)

    reader_job = proc.spawn(reader)

    reports_due = []
    with api.timeout(TIMEOUT, None):
        for label, size, content_type, success_report, failure_report, chunk_size in MESSAGES:
            message_id, digest = send(session, label, size, content_type, success_report,
                                      failure_report, chunk_size)
            out(event='message', label=label, message_id=message_id, size=size, sha256=digest)
            if success_report:
                reports_due.append(message_id)

        # the other end's messages, and the REPORTs asked of it
        while len(received) < EXPECTED or not all(m in reported for m in reports_due):
            api.sleep(0.05)

    # a response that should not come has had time to
    api.sleep(1)
    out(event='done', received=len(received), reported=sorted(reported))
    reader_job.kill()
    session.shutdown()


if __name__ == '__main__':
    failed = []

    def run():
        try:
            main()
        except BaseException:
            traceback.print_exc()
            failed.append(True)
        finally:
            reactor.stop()

    reactor.callWhenRunning(proc.spawn, run)
    reactor.run()
    sys.exit(1 if failed else 0)
