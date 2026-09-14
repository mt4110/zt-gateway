{
  description = "Zero-Trust Local Gateway Architecture";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      perSystem = system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          go = pkgs.go_1_27;
          buildGoModule = pkgs.buildGoModule.override { inherit go; };
        
          zt-bin = buildGoModule {
            pname = "zt-bin";
            version = "0.1.0";
            src = ./gateway/zt;
            vendorHash = "sha256-HMJtMe1FuAu8OikIF7zl8jMPokjnHBe8+Tp2NitZWr4=";
            env.GOWORK = "off";
            doCheck = false;
          };
          secure-scan = buildGoModule {
            pname = "secure-scan";
            version = "0.1.0";
            src = ./tools/secure-scan;
            vendorHash = "sha256-QIyko96MxpqBdaov9DA8sHfrWVUqb4RBVAD20IyYehg=";
            env.GOWORK = "off";
            doCheck = false;
          };
          secure-pack = buildGoModule {
            pname = "secure-pack";
            version = "0.1.0";
            src = ./tools/secure-pack;
            vendorHash = "sha256-bE26O5vxPoH36ty71rYwFVlOdKgpthpzAfM4lYUXLqQ=";
            env.GOWORK = "off";
            doCheck = false;
          };
          secure-rebuild = buildGoModule {
            pname = "secure-rebuild";
            version = "0.1.0";
            src = ./tools/secure-rebuild;
            vendorHash = null;
            env.GOWORK = "off";
            doCheck = false;
          };
        
          zt = pkgs.symlinkJoin {
            name = "zt";
            paths = [ zt-bin ];
            buildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              wrapProgram $out/bin/zt \
                --prefix PATH : ${pkgs.lib.makeBinPath [ secure-scan secure-pack secure-rebuild go pkgs.gnupg pkgs.gnutar ]}
            '';
          };

        in
        {
          packages = {
            inherit zt-bin secure-scan secure-pack secure-rebuild zt;
            default = zt;
          };

          devShells.default = pkgs.mkShell {
            buildInputs = [
              go
              pkgs.gopls
              pkgs.gotools
              pkgs.go-tools
              pkgs.gnupg
              pkgs.gnutar
              pkgs.nodejs_24
              pkgs.python3
              # Now these variables are in scope
              secure-scan
              secure-pack
              secure-rebuild
            ];
          };
        };
    in
    {
      packages = forAllSystems (system: (perSystem system).packages);
      devShells = forAllSystems (system: (perSystem system).devShells);
    };
}
