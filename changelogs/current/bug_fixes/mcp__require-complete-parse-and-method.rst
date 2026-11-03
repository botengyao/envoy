Fixed the :ref:`MCP filter <config_http_filters_mcp>` to only report ``is_mcp_request`` as ``true`` when the root JSON
object has been parsed to completion and a non-empty ``method`` (or valid JSON-RPC response) is present, and to clear
method-derived validity on any JSON parse error. Previously, a parse error occurring after ``"method"`` was seen (such as
excessive nesting depth or an invalid UTF-16 lone surrogate) or an empty ``"method"`` could leave ``is_mcp_request`` set
to ``true`` in ``PASS_THROUGH`` mode without a valid ``method`` in metadata.
