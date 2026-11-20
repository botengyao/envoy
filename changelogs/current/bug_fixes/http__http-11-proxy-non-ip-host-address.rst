Fixed a crash in the ``envoy.transport_sockets.http_11_proxy`` upstream transport socket when the
upstream host had a non-empty ``hostname`` and a non-IP address (such as ``pipe`` or
``envoy_internal_address``), or a null host address. The socket now falls back to the address
string when no IP port is available, matching the behavior for hosts with an empty hostname.
