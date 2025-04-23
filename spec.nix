{
  lib,
  teamName,
  pname,
  imageName,
  ...
}: let
  name = pname;
  namespace = teamName;
  upstreamUmamiFQDN = "reops-umami-beta";
  naisApp = {
    apiVersion = "nais.io/v1alpha1";
    kind = "Application";
    metadata = {
      inherit name namespace;
      labels = {
        team = teamName;
        apiserver-access = "enabled";
      };
      annotations = {
        # V These can be tuned, for sure
        "config.linkerd.io/proxy-cpu-limit" = "4"; # Ridic number
        "config.linkerd.io/proxy-cpu-request" = "500m";
        "config.linkerd.io/proxy-memory-request" = "512Mi";
        "config.linkerd.io/proxy-memory-limit" = "1024Mi";
        "config.linkerd.io/proxy-inbound-connect-timeout" = "500ms";
        "config.linkerd.io/proxy-outbound-connect-timeout" = "500ms";
      };
    };
    spec = {
      ingresses = ["https://umami.nav.no/api/send"];
      image = "europe-north1-docker.pkg.dev/nais-management-233d/${teamName}/${imageName}";
      port = 6191;
      liveness = {
        failureThreshold = 10;
        initialDelay = 2;
        path = "/is_alive";
        periodSeconds = 10;
        port = 6969;
        timeout = 1;
      };
      prometheus = {
        enabled = true;
        path = "/metrics";
        port = "9090";
      };
      replicas = {
        min = 2;
        max = 6;
        cpuThresholdPercentage = 50;
        scalingStrategy.cpu.thresholdPercentage = 50;
      };
      accessPolicy.outbound.rules = [{application = upstreamUmamiFQDN;}];
      resources = {
        requests = {
          cpu = "100m";
          memory = "256Mi";
        };
      };
      env = lib.attrsToList {
        RUST_LOG = "INFO";
        UMAMI_HOST = "${upstreamUmamiFQDN}.${teamName}.svc.cluster.local";
        UMAMI_PORT = "80";
      };
    };
  };
in [naisApp]
