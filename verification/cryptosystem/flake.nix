{
  description = "Reproducible Agentknock v1 symbolic-verification toolchain";

  inputs.nixpkgs.url =
    "github:NixOS/nixpkgs/e5bdc4a41d4c072fe1e3787eaa0320a384741d44";

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      verifpal = pkgs.rustPlatform.buildRustPackage rec {
        pname = "verifpal";
        version = "1.0.0";

        src = pkgs.fetchFromGitHub {
          owner = "symbolicsoft";
          repo = "verifpal";
          rev = "c9c7a6006a3629f5a10cde6d2d6e726f212e9e64";
          hash = "sha256-rt3ybZPk7tDp/u0+LAc9+xx4x2fpPzaDQpx6iOzL8h4=";
        };

        cargoHash = "sha256-eV9p/j2RNt+ZY/3bjgui0at4KoE7h5ngHb2c2h0d39Y=";
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
          cargo
          coreutils
          git
          gnugrep
          gnused
          proverif
          rustc
          tamarin-prover
        ] ++ [ verifpal ];
      };
    };
}
