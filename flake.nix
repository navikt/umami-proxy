{
  description =
    "A Nix-flake based development interface for NAV's Statusplattform's K8s operator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Rust compile stuff
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };

    # Rust 3rd party tooling
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, ... }@inputs:
    inputs.flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [ (import inputs.rust-overlay) ];
        };
        inherit (pkgs) lib;

        craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common vars
        cargoDetails = pkgs.lib.importTOML ./Cargo.toml;
        pname = cargoDetails.package.name;
        src = craneLib.cleanCargoSource (craneLib.path ./.);
        commonArgs = {
          inherit pname src CARGO_BUILD_TARGET;

          buildInputs = with pkgs; [ openssl ];
          nativeBuildInputs = with pkgs;
            [ pkg-config cmake perl ] ++ lib.optionals stdenv.isDarwin [
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.SystemConfiguration
            ];
        };

        imageTag = "v${cargoDetails.package.version}-${dockerTag}";
        imageName = "${pname}:${imageTag}";
        teamName = "team-researchops";
        my-spec = import ./spec.nix { inherit lib teamName pname imageName; };

        # Compile (and cache) cargo dependencies _only_
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        cargo-sbom = craneLib.mkCargoDerivation (commonArgs // {
          # Require the caller to specify cargoArtifacts we can use
          inherit cargoArtifacts;

          # A suffix name used by the derivation, useful for logging
          pnameSuffix = "-sbom";

          # Set the cargo command we will use and pass through the flags
          installPhase = "mv bom.json $out";
          buildPhaseCargoCommand =
            "cargo cyclonedx -f json --all --override-filename bom";
          nativeBuildInputs = (commonArgs.nativeBuildInputs or [ ])
            ++ [ pkgs.cargo-cyclonedx ];
        });

        dockerTag = if lib.hasAttr "rev" self then
          "${builtins.toString self.revCount}-${self.shortRev}"
        else
          "gitDirty";

        # Compile workspace code (including 3rd party dependencies)
        cargo-package =
          craneLib.buildPackage (commonArgs // { inherit cargoArtifacts; });
      in {
        checks = {
          inherit cargo-package cargo-sbom;
          # Run clippy (and deny all warnings) on the crate source,
          # again, resuing the dependency artifacts from above.
          #
          # Note that this is done as a separate derivation so that
          # we can block the CI if there are issues here, but not
          # prevent downstream consumers from building our crate by itself.
          cargo-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = lib.concatStringsSep " " [ ];
          });
          cargo-doc =
            craneLib.cargoDoc (commonArgs // { inherit cargoArtifacts; });
          cargo-fmt = craneLib.cargoFmt { inherit src; };
          cargo-audit = craneLib.cargoAudit {
            inherit (inputs) advisory-db;
            inherit src;
          };
        };
        devShells.default = craneLib.devShell {
          packages = with pkgs;
            [
              cargo-audit
              cargo-auditable
              cargo-deny
              cargo-outdated
              cargo-cyclonedx
              cargo-watch
              cmake
              socat

              # Editor stuffs
              lldb
              rust-analyzer
            ] ++ lib.optionals stdenv.isDarwin [
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.SystemConfiguration
            ];

          shellHook = ''
            ${rustToolchain}/bin/cargo --version
            ${pkgs.helix}/bin/hx --health rust
          '';
        };

        packages = rec {
          default = rust;
          rust = cargo-package;
          sbom = cargo-sbom;
          image = docker;
          spec = let
            toJson = attrSet: builtins.toJSON attrSet;
            yamlContent = builtins.concatStringsSep ''

              ---
            '' (map toJson my-spec);
          in pkgs.writeText "spec.yaml" yamlContent;

          docker = pkgs.dockerTools.buildImage {
            name = pname;
            tag = imageTag;
            config.Entrypoint = [ "${cargo-package}/bin/${pname}" ];
          };
        };

        # Now `nix fmt` works!
        formatter = pkgs.alejandra;
      });
}
