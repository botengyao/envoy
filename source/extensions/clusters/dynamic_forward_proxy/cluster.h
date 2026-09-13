#pragma once

#include "envoy/config/cluster/v3/cluster.pb.h"
#include "envoy/config/endpoint/v3/endpoint_components.pb.h"
#include "envoy/extensions/clusters/dns/v3/dns_cluster.pb.h"
#include "envoy/extensions/clusters/dynamic_forward_proxy/v3/cluster.pb.h"
#include "envoy/extensions/clusters/dynamic_forward_proxy/v3/cluster.pb.validate.h"
#include "envoy/http/conn_pool.h"

#include "source/common/upstream/cluster_factory_impl.h"
#include "source/extensions/clusters/common/logical_host.h"
#include "source/extensions/common/dynamic_forward_proxy/cluster_store.h"
#include "source/extensions/common/dynamic_forward_proxy/dns_cache.h"
#include "source/extensions/common/dynamic_forward_proxy/dynamic_host_candidates.h"

namespace Envoy {
namespace Extensions {
namespace Clusters {
namespace DynamicForwardProxy {

class ClusterFactory;
class ClusterTest;

// Presents a host's DNS name as SNI and as the SAN to verify, and keeps every other
// request-derived transport socket option.
class HostTlsIdentityTransportSocketOptions : public Network::TransportSocketOptions {
public:
  HostTlsIdentityTransportSocketOptions(
      const std::optional<std::string>& server_name,
      const std::vector<std::string>& verify_san_list,
      Network::TransportSocketOptionsConstSharedPtr inner_options);

  // Network::TransportSocketOptions
  const std::optional<std::string>& serverNameOverride() const override { return server_name_; }
  const std::vector<std::string>& verifySubjectAltNameListOverride() const override {
    return verify_san_list_;
  }
  const std::vector<std::string>& applicationProtocolListOverride() const override {
    return inner_options_->applicationProtocolListOverride();
  }
  const std::vector<std::string>& applicationProtocolFallback() const override {
    return inner_options_->applicationProtocolFallback();
  }
  std::optional<Network::ProxyProtocolData> proxyProtocolOptions() const override {
    return inner_options_->proxyProtocolOptions();
  }
  OptRef<const Http11ProxyInfo> http11ProxyInfo() const override {
    return inner_options_->http11ProxyInfo();
  }
  const StreamInfo::FilterState::Objects& downstreamSharedFilterStateObjects() const override {
    return inner_options_->downstreamSharedFilterStateObjects();
  }

private:
  const std::optional<std::string> server_name_;
  const std::vector<std::string> verify_san_list_;
  const Network::TransportSocketOptionsConstSharedPtr inner_options_;
};

// A dynamic forward proxy host whose TLS connections use the host's own DNS name.
class TlsIdentityLogicalHost : public Upstream::LogicalHost {
public:
  static absl::StatusOr<std::unique_ptr<Upstream::LogicalHost>>
  create(const Upstream::ClusterInfoConstSharedPtr& cluster, const std::string& hostname,
         const Network::Address::InstanceConstSharedPtr& address,
         const Upstream::HostDescription::AddressVector& address_list,
         const envoy::config::endpoint::v3::LocalityLbEndpoints& locality_lb_endpoint,
         const envoy::config::endpoint::v3::LbEndpoint& lb_endpoint);

  const std::optional<std::string>& serverName() const { return server_name_; }
  const std::vector<std::string>& verifySanList() const { return verify_san_list_; }

  // Upstream::Host
  CreateConnectionData createConnection(
      Event::Dispatcher& dispatcher, const Network::ConnectionSocket::OptionsSharedPtr& options,
      Network::TransportSocketOptionsConstSharedPtr transport_socket_options) const override;

private:
  TlsIdentityLogicalHost(
      const Upstream::ClusterInfoConstSharedPtr& cluster, const std::string& hostname,
      const Network::Address::InstanceConstSharedPtr& address,
      const Upstream::HostDescription::AddressVector& address_list,
      const envoy::config::endpoint::v3::LocalityLbEndpoints& locality_lb_endpoint,
      const envoy::config::endpoint::v3::LbEndpoint& lb_endpoint, absl::Status& creation_status);

  std::optional<std::string> server_name_;
  std::vector<std::string> verify_san_list_;
};

class Cluster : public Upstream::BaseDynamicClusterImpl,
                public Extensions::Common::DynamicForwardProxy::DfpCluster,
                public Extensions::Common::DynamicForwardProxy::DnsCache::UpdateCallbacks {
public:
  ~Cluster() override;

  // Upstream::Cluster
  Upstream::Cluster::InitializePhase initializePhase() const override {
    return Upstream::Cluster::InitializePhase::Primary;
  }

  // Upstream::ClusterImplBase
  void startPreInit() override;

  // Extensions::Common::DynamicForwardProxy::DnsCache::UpdateCallbacks
  absl::Status onDnsHostAddOrUpdate(
      const std::string& host,
      const Extensions::Common::DynamicForwardProxy::DnsHostInfoSharedPtr& host_info) override;
  void onDnsHostRemove(const std::string& host) override;
  void onDnsResolutionComplete(const std::string&,
                               const Extensions::Common::DynamicForwardProxy::DnsHostInfoSharedPtr&,
                               Network::DnsResolver::ResolutionStatus) override {}

  bool allowCoalescedConnections() const { return allow_coalesced_connections_; }
  bool enableSubCluster() const override { return enable_sub_cluster_; }
  Upstream::HostSelectionResponse chooseHost(absl::string_view host,
                                             Upstream::LoadBalancerContext* context) const;

  // Extensions::Common::DynamicForwardProxy::DfpCluster
  std::pair<bool, std::optional<envoy::config::cluster::v3::Cluster>>
  createSubClusterConfig(const std::string& cluster_name, const std::string& host,
                         const int port) override;
  bool touch(const std::string& cluster_name) override;
  void checkIdleSubCluster();
  Upstream::HostConstSharedPtr findHostByName(const std::string& host) const;

protected:
  Cluster(const envoy::config::cluster::v3::Cluster& cluster,
          Extensions::Common::DynamicForwardProxy::DnsCacheSharedPtr&& cacahe,
          const envoy::extensions::clusters::dynamic_forward_proxy::v3::ClusterConfig& config,
          Upstream::ClusterFactoryContext& context,
          Extensions::Common::DynamicForwardProxy::DnsCacheManagerSharedPtr&& cache_manager,
          absl::Status& creation_status);

private:
  friend class ClusterFactory;
  friend class ClusterTest;

  struct ClusterInfo {
    ClusterInfo(std::string cluster_name, Cluster& parent);
    void touch();
    bool checkIdle();

    std::string cluster_name_;
    Cluster& parent_;
    std::atomic<std::chrono::steady_clock::duration> last_used_time_;
  };

  using ClusterInfoMap = absl::flat_hash_map<std::string, std::shared_ptr<ClusterInfo>>;

  struct HostInfo {
    HostInfo(const Extensions::Common::DynamicForwardProxy::DnsHostInfoSharedPtr& shared_host_info,
             const Upstream::LogicalHostSharedPtr& logical_host)
        : shared_host_info_(shared_host_info), logical_host_(logical_host) {}

    const Extensions::Common::DynamicForwardProxy::DnsHostInfoSharedPtr shared_host_info_;
    const Upstream::LogicalHostSharedPtr logical_host_;
  };

  using HostInfoMap = absl::flat_hash_map<std::string, HostInfo>;

  class DFPHostSelectionHandle;

  class LoadBalancer : public Upstream::LoadBalancer,
                       public Extensions::Common::DynamicForwardProxy::DfpLb,
                       public Envoy::Http::ConnectionPool::ConnectionLifetimeCallbacks {
  public:
    LoadBalancer(std::weak_ptr<const Cluster> cluster) : cluster_(cluster) {}
    ~LoadBalancer() override;

    // DfpLb
    Upstream::HostConstSharedPtr findHostByName(const std::string& host) const override;
    // Upstream::LoadBalancer
    Upstream::HostSelectionResponse chooseHost(Upstream::LoadBalancerContext* context) override;
    // Preconnecting not implemented.
    Upstream::HostConstSharedPtr peekAnotherHost(Upstream::LoadBalancerContext*) override {
      return nullptr;
    }
    std::optional<Upstream::SelectedPoolAndConnection>
    selectExistingConnection(Upstream::LoadBalancerContext* context, const Upstream::Host& host,
                             std::vector<uint8_t>& hash_key) override;
    OptRef<Envoy::Http::ConnectionPool::ConnectionLifetimeCallbacks> lifetimeCallbacks() override;

    // Moves the current attempt past a host candidate whose lookup found no host.
    Upstream::HostSelectionResponse chooseNextCandidateHost(Upstream::LoadBalancerContext* context);

    // Envoy::Http::ConnectionPool::ConnectionLifetimeCallbacks
    void onConnectionOpen(Envoy::Http::ConnectionPool::Instance& pool,
                          std::vector<uint8_t>& hash_key,
                          const Network::Connection& connection) override;

    void onConnectionDraining(Envoy::Http::ConnectionPool::Instance& pool,
                              std::vector<uint8_t>& hash_key,
                              const Network::Connection& connection) override;

  private:
    Upstream::HostSelectionResponse selectHost(const Cluster& cluster,
                                               Upstream::LoadBalancerContext* context,
                                               absl::string_view raw_host, uint32_t port,
                                               const std::string& hostname, bool from_candidates);
    Upstream::HostSelectionResponse
    chooseCandidateHost(const Cluster& cluster, Upstream::LoadBalancerContext* context,
                        Common::DynamicForwardProxy::DynamicHostCandidates& candidates,
                        uint32_t attempt, std::optional<uint32_t> index);

    struct ConnectionInfo {
      Envoy::Http::ConnectionPool::Instance* pool_; // Not a ref to allow assignment in remove().
      const Network::Connection* connection_;       // Not a ref to allow assignment in remove().
    };
    struct LookupKey {
      const std::vector<uint8_t> hash_key_;
      const Network::Address::Instance& peer_address_;
      bool operator==(const LookupKey& rhs) const {
        return std::tie(hash_key_, peer_address_) == std::tie(rhs.hash_key_, rhs.peer_address_);
      }
    };
    struct LookupKeyHash {
      size_t operator()(const LookupKey& lookup_key) const {
        return std::hash<std::string>{}(lookup_key.peer_address_.asString());
      }
    };

    absl::flat_hash_map<LookupKey, std::vector<ConnectionInfo>, LookupKeyHash> connection_info_map_;
    absl::flat_hash_set<DFPHostSelectionHandle*> pending_host_selection_handles_;
    std::weak_ptr<const Cluster> cluster_;
  };

  // This acts as the bridge for asynchronous host lookup. If the host is not
  // present in the DFP cluster, the DFPHostSelectionHandle will receive a onLoadDnsCacheComplete
  // call unless the LoadDnsCacheEntryHandlePtr is destroyed. Destruction of the
  // LoadDnsCacheEntryHandlePtr ensures that no callback will occur, at which
  // point it is safe to delete the DFPHostSelectionHandle.
  class DFPHostSelectionHandle
      : public Upstream::AsyncHostSelectionHandle,
        public Common::DynamicForwardProxy::DnsCache::LoadDnsCacheEntryCallbacks {
  public:
    DFPHostSelectionHandle(
        Upstream::LoadBalancerContext* context, std::weak_ptr<const Cluster> cluster,
        std::string hostname,
        absl::flat_hash_set<DFPHostSelectionHandle*>& pending_host_selection_handles)
        : context_(context), cluster_(cluster), hostname_(hostname),
          pending_host_selection_handles_(pending_host_selection_handles) {}

    // Ideally the cancel() will be called to cancel the async host selection before the handle is
    // destructed. In case it is not, the destructor will also ensure the cancellation of the async
    // host selection to avoid calling back into the load balancer after it is destructed.
    ~DFPHostSelectionHandle() override { cancel(); }

    void cancel() override {
      // Cancels the DNS callback.
      handle_.reset();
      if (chained_ != nullptr) {
        chained_->cancel();
      }

      if (pending_host_selection_handles_.has_value()) {
        // Removes itself from the pending host selection handles so that the cluster will not
        // attempt to call onLoadDnsCacheComplete after cancellation.
        pending_host_selection_handles_->erase(this);
        pending_host_selection_handles_.reset();
      }
    }

    void
    onLoadDnsCacheComplete(const Common::DynamicForwardProxy::DnsHostInfoSharedPtr& info) override {
      Upstream::HostConstSharedPtr host;
      if (auto cluster = cluster_.lock()) {
        host = cluster->findHostByName(hostname_);
      }
      std::string details = info->details();
      if (pending_host_selection_handles_.has_value()) {
        pending_host_selection_handles_->erase(this);
        pending_host_selection_handles_.reset();
      }
      if (host == nullptr && load_balancer_ != nullptr) {
        // The finished lookup must not hold a pending request slot the next lookup may need.
        handle_.reset();
        auto_dec_.reset();
        Upstream::HostSelectionResponse next = load_balancer_->chooseNextCandidateHost(context_);
        if (next.cancelable != nullptr) {
          // The router only knows this handle, so this handle owns cancellation of the next lookup.
          chained_ = std::move(next.cancelable);
          return;
        }
        host = std::move(next.host);
        details = std::move(next.details);
      }
      context_->onAsyncHostSelection(std::move(host), std::move(details));
    }

    void setHandle(Common::DynamicForwardProxy::DnsCache::LoadDnsCacheEntryHandlePtr&& handle) {
      handle_ = std::move(handle);
    }
    void setAutoDec(Upstream::ResourceAutoIncDecPtr&& dec) { auto_dec_ = std::move(dec); }
    // Set for host candidates, whose failed lookups continue with the next candidate.
    void setLoadBalancer(LoadBalancer& load_balancer) { load_balancer_ = &load_balancer; }

  private:
    friend class LoadBalancer;

    Upstream::LoadBalancerContext* context_;
    Common::DynamicForwardProxy::DnsCache::LoadDnsCacheEntryHandlePtr handle_;
    Upstream::ResourceAutoIncDecPtr auto_dec_;
    std::weak_ptr<const Cluster> cluster_;
    std::string hostname_;
    OptRef<absl::flat_hash_set<DFPHostSelectionHandle*>> pending_host_selection_handles_;
    LoadBalancer* load_balancer_{};
    std::unique_ptr<Upstream::AsyncHostSelectionHandle> chained_;
  };

  class LoadBalancerFactory : public Upstream::LoadBalancerFactory {
  public:
    LoadBalancerFactory(std::weak_ptr<const Cluster> cluster) : cluster_(std::move(cluster)) {}

    // Upstream::LoadBalancerFactory
    Upstream::LoadBalancerPtr create(Upstream::LoadBalancerParams) override {
      return std::make_unique<LoadBalancer>(cluster_);
    }
    bool recreateOnHostChangeDeprecated() const override { return false; }

  private:
    std::weak_ptr<const Cluster> cluster_;
  };

  class ThreadAwareLoadBalancer : public Upstream::ThreadAwareLoadBalancer {
  public:
    ThreadAwareLoadBalancer(std::weak_ptr<const Cluster> cluster) : cluster_(std::move(cluster)) {}

    // Upstream::ThreadAwareLoadBalancer
    Upstream::LoadBalancerFactorySharedPtr factory() override {
      return std::make_shared<LoadBalancerFactory>(cluster_);
    }
    absl::Status initialize() override { return absl::OkStatus(); }

  private:
    std::weak_ptr<const Cluster> cluster_;
  };

  absl::Status
  addOrUpdateHost(absl::string_view host,
                  const Extensions::Common::DynamicForwardProxy::DnsHostInfoSharedPtr& host_info,
                  std::unique_ptr<Upstream::HostVector>& hosts_added)
      ABSL_LOCKS_EXCLUDED(host_map_lock_);

  void updatePriorityState(const Upstream::HostVector& hosts_added,
                           const Upstream::HostVector& hosts_removed)
      ABSL_LOCKS_EXCLUDED(host_map_lock_);

  const Extensions::Common::DynamicForwardProxy::DnsCacheManagerSharedPtr dns_cache_manager_;
  const Extensions::Common::DynamicForwardProxy::DnsCacheSharedPtr dns_cache_;
  const Extensions::Common::DynamicForwardProxy::DnsCache::AddUpdateCallbacksHandlePtr
      update_callbacks_handle_;
  const envoy::config::endpoint::v3::LocalityLbEndpoints dummy_locality_lb_endpoint_;
  const envoy::config::endpoint::v3::LbEndpoint dummy_lb_endpoint_;
  const LocalInfo::LocalInfo& local_info_;
  Event::Dispatcher& main_thread_dispatcher_;
  const envoy::config::cluster::v3::Cluster orig_cluster_config_;

  Event::TimerPtr idle_timer_;

  // True if H2 and H3 connections may be reused across different origins.
  const bool allow_coalesced_connections_;
  const bool tls_identity_from_host_;

  mutable absl::Mutex host_map_lock_;
  HostInfoMap host_map_ ABSL_GUARDED_BY(host_map_lock_);

  mutable absl::Mutex cluster_map_lock_;
  ClusterInfoMap cluster_map_ ABSL_GUARDED_BY(cluster_map_lock_);

  TimeSource& time_source_;
  Upstream::ClusterManager& cm_;
  const size_t max_sub_clusters_;
  const std::chrono::milliseconds sub_cluster_ttl_;
  const envoy::config::cluster::v3::Cluster_LbPolicy sub_cluster_lb_policy_;
  const bool enable_sub_cluster_;

  // Optional DNS configuration for dynamically created sub clusters. When set, sub clusters are
  // created using the DnsCluster extension rather than the legacy STRICT_DNS discovery type.
  const std::optional<envoy::extensions::clusters::dns::v3::DnsCluster> sub_cluster_dns_config_;

  friend class ClusterFactory;
  friend class ClusterTest;
};

class ClusterFactory : public Upstream::ConfigurableClusterFactoryBase<
                           envoy::extensions::clusters::dynamic_forward_proxy::v3::ClusterConfig> {
public:
  ClusterFactory() : ConfigurableClusterFactoryBase("envoy.clusters.dynamic_forward_proxy") {}

private:
  absl::StatusOr<
      std::pair<Upstream::ClusterImplBaseSharedPtr, Upstream::ThreadAwareLoadBalancerPtr>>
  createClusterWithConfig(
      const envoy::config::cluster::v3::Cluster& cluster,
      const envoy::extensions::clusters::dynamic_forward_proxy::v3::ClusterConfig& proto_config,
      Upstream::ClusterFactoryContext& context) override;
};

DECLARE_FACTORY(ClusterFactory);

} // namespace DynamicForwardProxy
} // namespace Clusters
} // namespace Extensions
} // namespace Envoy
