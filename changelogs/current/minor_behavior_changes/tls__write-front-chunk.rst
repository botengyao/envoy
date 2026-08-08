The TLS transport socket no longer linearizes the full 16KB write chunk before every ``SSL_write``.
The front slice of the write buffer is now handed to ``SSL_write`` as is when it holds at least 4KB,
and a shorter one is coalesced only up to 4KB instead of the whole chunk. A single short slice at
the front of the buffer, such as response headers, used to misalign the slice boundaries against
every following chunk, so that the whole egress stream was copied an extra time; it now costs one
small copy. A fragmented buffer can produce TLS records smaller than 16KB. This can be reverted by
setting ``envoy.reloadable_features.tls_write_front_chunk`` to ``false``.
