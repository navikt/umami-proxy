{ lib, teamName, pname, imageName, ... }:
let
  naisApp = {
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
        scalingStrategy.cpu.thresholdPercentage = 50;
      };
      accessPolicy.outbound.external =
        [ { host = "api.eu.amplitude.com"; } { host = "cdn.amplitude.com"; } ];
      resources = {
        limits.memory = "512Mi";
        requests = {
          cpu = "200m";
          memory = "256Mi";
        };
      };
      skipCaBundle = true;
      env = lib.attrsToList { AMPLITUDE_URL = "api.eu.amplitude.com:80"; };
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
      egress = [{ to = [{ ipBlock.cidr = "0.0.0.0/0"; }]; }];
      podSelector.matchLabels.app = pname;
      policyTypes = [ "Egress" ];
    };
  };

  canaryIngress = {
    apiVersion = "networking.k8s.io/v1";
    kind = "Ingress";
    metadata = {
      name = "${pname}-canary-ingress";
      namespace = teamName;
      labels = {
        app = pname;
        team = teamName;
      };
      annotations = {
        "nginx.ingress.kubernetes.io/backend-protocol" = "HTTP";
        "nginx.ingress.kubernetes.io/canary" = "true";
        "nginx.ingress.kubernetes.io/canary-weight" = "10";
        "nginx.ingress.kubernetes.io/use-regex" = "true";
        "prometheus.io/path" = "/is_alive";
        "prometheus.io/scrape" = "true";
      };
    };
    spec = {
      ingressClassName = "nais-ingress";
      rules = [{
        host = "amplitude.intern.dev.nav.no";
        http.paths = [{
          backend.service = {
            name = pname;
            port.number = 80;
          };
          path = "/";
          pathType = "ImplementationSpecific";
        }];
      }];
    };
  };
in [ naisApp allowAllEgress canaryIngress ]
