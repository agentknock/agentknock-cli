{
  description = "Reproducible Agentknock distribution build";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs =
    { nixpkgs, ... }:
    let
      targets = {
        aarch64-darwin = {
          rust = "aarch64-apple-darwin";
          static = false;
        };
        aarch64-linux = {
          rust = "aarch64-unknown-linux-musl";
          static = true;
        };
        x86_64-linux = {
          rust = "x86_64-unknown-linux-musl";
          static = true;
        };
      };
      manifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      source = nixpkgs.lib.fileset.toSource {
        root = ./.;
        fileset = nixpkgs.lib.fileset.unions [
          ./Cargo.lock
          ./Cargo.toml
          ./src
        ];
      };

      packages = nixpkgs.lib.mapAttrs (
        system: target:
        let
          pkgs = import nixpkgs { inherit system; };
          buildPkgs = if target.static then pkgs.pkgsStatic else pkgs;

          agentknock = buildPkgs.rustPlatform.buildRustPackage {
            pname = "agentknock";
            inherit (manifest.package) version;
            src = source;

            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "--bin"
              "agentknock"
            ];
            doCheck = false;

            nativeBuildInputs = [
              pkgs.cmake
              pkgs.perl
            ] ++ pkgs.lib.optional target.static pkgs.binutils;

            LC_ALL = "C";
            SOURCE_DATE_EPOCH = "1";
            TZ = "UTC";

            postFixup = pkgs.lib.optionalString target.static ''
              if ${pkgs.binutils}/bin/readelf --program-headers "$out/bin/agentknock" \
                | grep --quiet INTERP; then
                echo "agentknock contains a dynamic interpreter" >&2
                exit 1
              fi

              if ${pkgs.binutils}/bin/readelf --dynamic "$out/bin/agentknock" 2>/dev/null \
                | grep --quiet NEEDED; then
                echo "agentknock has a dynamic library dependency" >&2
                exit 1
              fi
            '';

            meta = {
              inherit (manifest.package) description homepage;
              license = with pkgs.lib.licenses; [
                asl20
                mit
              ];
              mainProgram = "agentknock";
              platforms = [ system ];
            };
          };

          dist =
            pkgs.runCommand "agentknock-${manifest.package.version}-${target.rust}-dist"
              {
                LC_ALL = "C";
                SOURCE_DATE_EPOCH = "1";
                TZ = "UTC";
                nativeBuildInputs = [
                  pkgs.coreutils
                  pkgs.gnutar
                  pkgs.gzip
                ];
              }
              ''
                archive="agentknock-${target.rust}.tar.gz"
                staging_dir=$(mktemp --directory)

                install -D --mode=0755 ${agentknock}/bin/agentknock "$staging_dir/agentknock"
                install -D --mode=0644 ${./LICENSE-APACHE} "$staging_dir/LICENSE-APACHE"
                install -D --mode=0644 ${./LICENSE-MIT} "$staging_dir/LICENSE-MIT"
                mkdir -p "$out"

                tar \
                  --sort=name \
                  --mtime='@1' \
                  --owner=0 \
                  --group=0 \
                  --numeric-owner \
                  --create \
                  --file=- \
                  --directory="$staging_dir" \
                  agentknock LICENSE-APACHE LICENSE-MIT \
                  | gzip --no-name > "$out/$archive"

                (cd "$out" && sha256sum "$archive" > "$archive.sha256")
              '';
        in
        {
          inherit agentknock dist;
          default = agentknock;
        }
      ) targets;
    in
    {
      inherit packages;

      checks = nixpkgs.lib.mapAttrs (system: _: { dist = packages.${system}.dist; }) targets;
    };
}
