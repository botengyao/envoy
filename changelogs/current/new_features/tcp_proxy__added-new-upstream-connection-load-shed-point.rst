Added the ``envoy.load_shed_points.tcp_proxy_new_upstream_connection``
:ref:`load shed point <config_overload_manager>` to the
:ref:`TCP proxy <config_network_filters_tcp_proxy>` filter. When it sheds, the filter stops
establishing a new upstream connection and closes the downstream connection without any connect
retries, incrementing the new ``downstream_cx_overload_shed`` counter and setting the ``OM``
response flag.
