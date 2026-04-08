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
      ingresses = ["https://umami.nav.no/api/send"];
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
        max = 3;
        cpuThresholdPercentage = 50;
      };
      accessPolicy.outbound.rules = [
        {
          application = "reops-event-proxy";
          namespace = "team-researchops";
        }
      ];
      resources = {
        requests = {
          cpu = "50m";
          memory = "32Mi";
        };
        limits = {
          memory = "124Mi";
        };
      };
    };
  };
in [naisApp]
