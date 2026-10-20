Fixed the router sending the request body to the upstream a second time when retries, shadowing
or internal redirects are enabled and an earlier HTTP filter stops iteration on the request
trailers (or on a later body frame) and then resumes it. The filter manager passes the router the
body it had already buffered, and the router now forwards only the bytes it has not sent yet. This
behavior can be reverted by setting the runtime guard
``envoy.reloadable_features.router_skip_replayed_request_body`` to ``false``.
