{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    go
    golangci-lint
    git
    jq
    kubectl
    kubectx
    kustomize
    kubernetes-helm
    nixd
  ];
}
