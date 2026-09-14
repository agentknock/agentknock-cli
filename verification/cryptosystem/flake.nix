{
  description = "Reproducible Agentknock v1 symbolic-verification toolchain";

  inputs.nixpkgs.url =
    "github:NixOS/nixpkgs/ef34387ddd751e1ab8857adf4676492d32eb24ec";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, rust-overlay, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      rustToolchain = pkgs.rust-bin.stable."1.98.1".minimal;
      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      };
      verifpal = rustPlatform.buildRustPackage rec {
        pname = "verifpal";
        version = "1.4.10";

        src = pkgs.fetchFromGitHub {
          owner = "symbolicsoft";
          repo = "verifpal";
          rev = "9e525f199e0fcef6b9df1280fed69cc999ee9afc";
          hash = "sha256-Cg8qaOGAGRYPacbv4WswcEkQrNRSh5xtO5y6gsUW3x8=";
        };

        cargoHash = "sha256-c5cnkZD5XPpYab0JOF8L5h7U5GbvHBzLXH1jq4b5Y1w=";

        # Upstream protocol-search tests must not run on every host core.
        checkFlags = [ "--test-threads=1" ];
        preCheck = "ulimit -v 8388608";
      };
    in
    {
      packages.${system} = {
        inherit verifpal;
        proverif = pkgs.proverif;
        tamarin = pkgs.tamarin-prover;
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          coreutils
          git
          gnugrep
          gnused
          proverif
          python3
          util-linux
          rustToolchain
          tamarin-prover
        ] ++ [ verifpal ];
      };
    };
}
