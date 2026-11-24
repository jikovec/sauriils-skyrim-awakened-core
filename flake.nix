{
  description = "Skyrim Awakened Core public source verification";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/02e08985a27c65ffd33d434eeb2e660a2e4dc84d";

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      mkSourceShell = pkgs.mkShell.override { stdenv = pkgs.llvmPackages_21.stdenv; };
    in {
      devShells.${system}.default = mkSourceShell {
        packages = with pkgs; [
          cargo rustc rustfmt clippy _7zz git pkg-config shellcheck actionlint
          (python3.withPackages (p: [ p.jsonschema p.rfc3339-validator p.pyyaml ]))
        ];
      };
    };
}
