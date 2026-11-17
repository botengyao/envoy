Fixed the filter manager dropping the body buffered by a filter that resumed from stopping all
iteration, stopped again on the replayed data, and then continued from its trailers callback. The
later filters, and the upstream or the client, received the trailers without the body. The buffered
body is now forwarded before the trailers. This change can be reverted by setting the runtime guard
``envoy.reloadable_features.filter_manager_forward_data_on_trailers_continue`` to ``false``.
