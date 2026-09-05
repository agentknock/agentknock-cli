{
  description = "Reproducible Agentknock v1 symbolic-verification toolchain";

  inputs.nixpkgs.url =
    "github:NixOS/nixpkgs/e5bdc4a41d4c072fe1e3787eaa0320a384741d44";
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
      rustToolchain = pkgs.rust-bin.stable."1.98.0".minimal;
      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      };
      verifpal = rustPlatform.buildRustPackage rec {
        pname = "verifpal";
        version = "1.4.3";

        src = pkgs.fetchFromGitHub {
          owner = "symbolicsoft";
          repo = "verifpal";
          rev = "035f11d0480674a519c4835c20438f7af24f2e92";
          hash = "sha256-UqmiO9mJiFRNsvVLuMrzvksu4QVY/9yD1hSG3vI1U90=";
        };

        cargoHash = "sha256-48l96oZz5TvZDub+uINttQK2PLQ0MQX4I8bx+dfPYMQ=";

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
