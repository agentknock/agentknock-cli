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
        version = "1.3.2";

        src = pkgs.fetchFromGitHub {
          owner = "symbolicsoft";
          repo = "verifpal";
          rev = "11ea59e2e044e564052e97e7444d375fb3bf4d39";
          hash = "sha256-0FeV/h/62W3GLP/4Q1qp51NjhWsZw7JD4/gCL41xLzM=";
        };

        cargoHash = "sha256-r8g0nyyGno4LeWmvj7EXVMw8uFEt7X2k7WIftvpC4LA=";
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
          rustToolchain
          tamarin-prover
        ] ++ [ verifpal ];
      };
    };
}
