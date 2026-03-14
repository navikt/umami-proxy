{
  lib,
  teamName,
  pname,
  imageName,
  ...
}: let
  name = pname;
  namespace = teamName;
  naisApp = {
    apiVersion = "nais.io/v1alpha1";
    kind = "Application";
    metadata = {
      inherit name namespace;
      labels = {
        team = teamName;
      };
    };
    spec = {
      ingresses = ["https://umami-dev.ekstern.dev.nav.no/api/send"];
      image = "europe-north1-docker.pkg.dev/nais-management-233d/${teamName}/${imageName}";
      port = 8080;
      liveness = {
        path = "/is_alive";
        port = 8080;
        initialDelay = 2;
        periodSeconds = 10;
        failureThreshold = 10;
        timeout = 1;
      };
      readiness = {
        path = "/is_ready";
        port = 8080;
        initialDelay = 2;
        periodSeconds = 10;
        failureThreshold = 10;
        timeout = 1;
      };
      replicas = {
        min = 1;
        max = 2;
        cpuThresholdPercentage = 80;
      };
      accessPolicy.outbound.rules = [
        {
          application = "reops-event-proxy";
          namespace = "team-researchops";
        }
      ];
      resources = {
        requests = {
          cpu = "800m";
          memory = "256Mi";
        };
        limits = {
          memory = "512Mi";
        };
      };
    };
  };
in [naisApp]
