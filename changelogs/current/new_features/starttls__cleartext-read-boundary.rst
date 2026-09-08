Added :ref:`max_cleartext_read_buffer_size
<envoy_v3_api_field_extensions.transport_sockets.starttls.v3.StartTlsConfig.max_cleartext_read_buffer_size>`
to the downstream StartTLS transport socket, bounding the total number of clear-text bytes read
before a switch to TLS. This keeps a ``ClientHello`` coalesced with the final clear-text message
out of the clear-text read buffer, where the TLS handshake could not consume it.
