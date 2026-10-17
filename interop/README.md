# Interop testing

## MSRP against msrplib

`tests/msrp_interop.rs` runs this library's MSRP against [msrplib](https://github.com/AGProjects/python3-msrplib), AG Projects' implementation of RFC 4975 used by Blink and SylkServer, over TCP on localhost. `msrplib/peer.py` is the msrplib end.

The tests are ignored by default, as they need a Python with msrplib. `msrplib/setup.sh` makes one, with the versions the tests were run with:

```sh
interop/msrplib/setup.sh /tmp/msrplib     # prints MSRPLIB_PYTHON=...
MSRPLIB_PYTHON=/tmp/msrplib/venv/bin/python cargo test --test msrp_interop -- --ignored
```

It needs `python3` (3.13 was used), `git` and libgnutls.

### What is tested

Both ways of setting up the connection:

- `we_connect_to_msrplib`: we connect, as for an `a=setup:active` of ours. msrplib waits for the connection, and the first chunk of our first message binds the session.
- `msrplib_connects_to_us`: msrplib connects to a session registered with `register_passive_channel` and given to `MsrpChannelManager::accept`, binding it with an empty SEND.

On each connection both ends send messages.

| Ours, to msrplib | Theirs, to us |
|---|---|
| 5 bytes, with success REPORTs | 5 bytes, with success REPORTs |
| 25 KB in three chunks, with success REPORTs | 25000 bytes in three chunks, each with `*` as range-end, with success REPORTs |
| 3000 bytes | 5000 bytes in one chunk, with `*` as range-end |
| a content type msrplib refuses | `Failure-Report: no` |
| | a content type we refuse |

The tests check:

- what arrives on each side, byte for byte, with its content type;
- that our three chunks arrive as `+`, `+`, `$`;
- the transaction responses each way: 200, or 415 for the refused content type;
- that we send no response to the chunk with `Failure-Report: no`; msrplib logs every chunk it receives, which shows this;
- our callbacks:
  - ending with 200 once msrplib's per-chunk success REPORTs cover the message;
  - ending with 415 for the message msrplib refuses;
- the success REPORTs we send:
  - one per message, covering all of it: `1-5/5` and `1-25000/25000`;
  - with no failure of the session.

### Results

Both tests pass with msrplib 0.21.3 (commit `212417d`). Nothing in this library needed changing for them.

Two things about msrplib itself came up while writing the peer:

- **`deliver_chunk()` with `Failure-Report: no`.** It is documented to return at once for such a chunk, but fails with an `AttributeError` instead. The peer sends that chunk with `send_chunk()`.
- **eventlib's Twisted hub and greenlet 3.** The hub cannot take over the main greenlet with greenlet 3, which Python 3.13 needs: it raises `AttributeError` where it expects `ValueError`. The peer runs the reactor in the main greenlet through `eventlib.twistedutil.join_reactor`, and msrplib in another greenlet.

### Not tested

- **TLS:** `msrps`.
- **Relays:** RFC 4976 relays, which this library does not support.
- **Aborting with `#`:** msrplib does not handle `#` (its session lists it as to-do).
- **CEMA:** CEMA chooses the address to connect to from the SDP, so there is nothing to test at the MSRP level.
- **Other:** keep-alives and multipart content.
