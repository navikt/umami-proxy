{ lib, teamName, pname, imageName, ... }:
let
  statusplattformNaisOperator = {
    apiVersion = "nais.io/v1alpha1";
    kind = "Application";
    metadata = {
      name = pname;
      namespace = teamName;
      labels.team = teamName;
    };
    spec = {
      image =
        "europe-north1-docker.pkg.dev/nais-management-233d/${teamName}/${imageName}";
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
        max = 4;
        cpuThresholdPercentage = 50;
        scalingStrategy = { cpu = { thresholdPercentage = 50; }; };
      };
      accessPolicy = {
        outbound = {
          external = [
            { host = "api.eu.amplitude.com"; }
            { host = "cdn.amplitude.com"; }
          ];
        };
      };
      resources = {
        limits = { memory = "512Mi"; };
        requests = {
          cpu = "200m";
          memory = "256Mi";
        };
      };
      service = {
        port = 6191;
        protocol = "http";
      };
      skipCaBundle = true;
      ingresses = [ "https://amplitude-2.intern.dev.nav.no" ];
      env = [{
        name = "AMPLITUDE_URL";
        value = "api.eu.amplitude.com:80";
      }];
    };
  };

  allowAllEgress = {
    apiVersion = "networking.k8s.io/v1";
    kind = "NetworkPolicy";
    metadata = {
      name = "amplitrude-proxy-eu-networkpolicy";
      namespace = teamName;
    };
    spec = {
      egress = [{ to = [{ ipBlock = { cidr = "0.0.0.0/0"; }; }]; }];
      podSelector = { matchLabels = { app = pname; }; };
      policyTypes = [ "Egress" ];
    };
  };

in [ statusplattformNaisOperator allowAllEgress ]
