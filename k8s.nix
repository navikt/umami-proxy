{ config, lib, pkgs, ... }:
# Im thinkng something like this
# let
#   notANaisSpec = {
#     name = "amplitrude";
#     image = "myrepo/myapp:1.0.0";
#     replicas = 3;
#     port = 8080;
#     resources = {
#       requests = { cpu = "100m"; memory = "128Mi"; };
#     };
#     ingressHost = "amplitrude.intern.nav.no";
#   };

#   k8sResources = callPackage ./generateResources.nix { spec = notANaisSpec; };
# in
# {
#   deployment = k8sResources.deploymentYaml;
#   service = k8sResources.serviceYaml;
#   ingress = k8sResources.ingressYaml;
# }

let
  generateDeployment = { name, image, replicas, port, resources }: ''
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: ${name}
    spec:
      replicas: ${toString replicas}
      selector:
        matchLabels:
          app: ${name}
      template:
        metadata:
          labels:
            app: ${name}
        spec:
          containers:
          - name: ${name}
            image: ${image}
            ports:
            - containerPort: ${toString port}
            resources:
              requests:
                cpu: ${resources.requests.cpu}
                memory: ${resources.requests.memory}
              limits:
                cpu: ${resources.limits.cpu}
                memory: ${resources.limits.memory}
  '';

  generateService = { name, port }: ''
    apiVersion: v1
    kind: Service
    metadata:
      name: ${name}
    spec:
      selector:
        app: ${name}
      ports:
      - protocol: TCP
        port: ${toString port}
        targetPort: ${toString port}
  '';

  generateIngress = { name, host }: ''
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: ${name}-ingress
    spec:
      rules:
      - host: ${host}
        http:
          paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ${name}
                port:
                  number: 80
  '';

in { spec }:
let
  deployment = generateDeployment {
    name = spec.name;
    image = spec.image;
    replicas = spec.replicas;
    port = spec.port; # SEVERAL PORTS, CARL
    resources = spec.resources;
  };

  service = generateService {
    name = spec.name;
    port = spec.port; # SEVERAL PORTS, CARL
  };

  ingress = generateIngress {
    name = spec.name;
    host = spec.ingressHost;
  };

in {
  deploymentYaml = deployment;
  serviceYaml = service;
  ingressYaml = ingress;
}
