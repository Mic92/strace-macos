{
  description = "System call tracer for macOS using LLDB";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      imports = [ inputs.treefmt-nix.flakeModule ];

      perSystem =
        {
          pkgs,
          lib,
          self',
          ...
        }:
        {
          packages.default = pkgs.stdenv.mkDerivation {
            pname = "strace-macos";
            version = "0.1.0";

            src = ./.;

            nativeBuildInputs = [ pkgs.makeWrapper ];

            installPhase = ''
              mkdir -p $out/libexec/strace-macos $out/bin

              # Copy Python source to libexec
              cp -r strace_macos $out/libexec/strace-macos/

              # Create wrapper that uses system Python
              makeWrapper /usr/bin/python3 $out/bin/strace \
                --add-flags "-m" \
                --add-flags "strace_macos" \
                --set PYTHONPATH "$out/libexec/strace-macos"
            '';

            meta = {
              description = "System call tracer for macOS using LLDB";
              mainProgram = "strace";
              platforms = pkgs.lib.platforms.darwin;
            };
          };

          checks = lib.mapAttrs' (n: lib.nameValuePair "package-${n}") self'.packages;

          treefmt = {
            projectRootFile = "flake.nix";
            programs.nixfmt.enable = true;
            programs.ruff-format.enable = true;
            programs.ruff-check.enable = true;
            programs.mypy.enable = true;
          };
        };
    };
}
