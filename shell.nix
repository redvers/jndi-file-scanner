with import <nixpkgs> {} ;
pkgs.mkShell {
  buildInputs = with pkgs; [
    pkg-config
    libzip
    ponyc
    pony-corral
    unzip
    pcre2
  ];
}
