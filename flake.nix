{
  description = "Zero-Trust Local Gateway Architecture";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        
        zt-bin = pkgs.buildGoModule {
            pname = "zt-bin";
            version = "0.1.0";
            src = ./gateway/zt;
            vendorHash = "sha256-dsmRXd5moOA08U2Hbi9Z3Hy1inZFiDOD9AMS56uk+8g=";
            env.GOWORK = "off";
            doCheck = false;
        };
        secure-scan = pkgs.buildGoModule {
            pname = "secure-scan";
            version = "0.1.0";
            src = ./tools/secure-scan;
            vendorHash = "sha256-XFVJWzU+36FXeoAtGYO/WAXxfgHXLEXxvAzeX8dmJo4=";
            env.GOWORK = "off";
            doCheck = false;
        };
        secure-pack = pkgs.buildGoModule {
            pname = "secure-pack";
            version = "0.1.0";
            src = ./tools/secure-pack;
            vendorHash = "sha256-5tCb1gPbdM3il1VmmGsdN4Wh5c7gFBiGqUqPKHKpvF0=";
            env.GOWORK = "off";
            doCheck = false;
        };
        secure-rebuild = pkgs.buildGoModule {
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
                --prefix PATH : ${pkgs.lib.makeBinPath [ secure-scan secure-pack secure-rebuild ]}
            '';
        };

      in
      {
        packages = {
            inherit zt-bin secure-scan secure-pack secure-rebuild zt;
            default = zt;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            gotools
            go-tools
            # Now these variables are in scope
            secure-scan
            secure-pack
            secure-rebuild
          ];
        };
      }
    );
}
