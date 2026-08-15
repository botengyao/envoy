TLS writes no longer re-linearize a permanently misaligned write buffer on every ``SSL_write()``.
When the front slice of the write buffer is shorter than the amount being written, ``linearize()``
copies into a freshly allocated 16KB slice and drains the same amount, which leaves the next slice
short by the same offset and so repeats the allocation and copy for every subsequent write. Envoy
now detects a second consecutive linearize and instead writes just the contiguous front slice,
which realigns the buffer at the cost of one short TLS record. The short record is skipped when the
write would drain the buffer completely, since no slice chain then remains to realign. Guarded by
runtime flag ``envoy.reloadable_features.tls_avoid_repeated_linearize`` (default ``true``); the flag
is read when a TLS connection is created, so setting it to ``false`` applies to new connections
rather than to connections that are already open.
