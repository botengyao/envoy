Data that the clear-text transport socket read past the end of the StartTLS negotiation, such as a
TLS ``ClientHello`` a client sends in the same packet as its last clear-text message, is now handed
to the TLS transport socket when a filter calls ``startSecureTransport()``. Previously it stayed in
the connection's read buffer and the TLS handshake could never see it. This can be disabled by
setting the runtime guard ``envoy.reloadable_features.secure_transport_read_buffer_handoff`` to
``false``.
