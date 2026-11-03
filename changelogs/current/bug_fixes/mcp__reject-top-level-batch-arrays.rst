Fixed the :ref:`MCP filter <config_http_filters_mcp>` to flag top-level JSON arrays (JSON-RPC batches) as invalid MCP
requests and stop parsing immediately. In ``REJECT_NO_MCP`` mode, top-level JSON arrays are rejected with HTTP ``400``
(``mcp_not_jsonrpc``); in ``PASS_THROUGH`` mode, dynamic metadata is now written with ``is_mcp_request: false`` and
``passthrough_reason: mcp_not_jsonrpc``.
