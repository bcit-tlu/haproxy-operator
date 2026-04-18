# Changelog

## [0.2.0](https://github.com/bcit-tlu/haproxy-operator/compare/haproxy-operator-v0.1.0...haproxy-operator-v0.2.0) (2026-04-18)


### Features

* scaffold haproxy-operator with Flux GitOps, SPIRE mTLS, and VSO integration ([7e80e93](https://github.com/bcit-tlu/haproxy-operator/commit/7e80e935b0ef2c450f562969e133b0e7149ad2e1))


### Bug Fixes

* address Devin Review findings — SPIRE lifecycle, double validation, dynamic RootCAs, unit tests ([4985dc0](https://github.com/bcit-tlu/haproxy-operator/commit/4985dc00b42410194f5440949ee438b06e4ac429))
* clear LastFailedHashAnnotation on successful apply ([0616620](https://github.com/bcit-tlu/haproxy-operator/commit/06166202ca8c472ba69125b8b5ce4593c9b989bd))
* retry client init on failure, context-aware waitForReady, deduplicate events ([f66f835](https://github.com/bcit-tlu/haproxy-operator/commit/f66f835116c4647aca056e4ce7b55b7729d67112))
* SPIRE source leak on client error, atomic file watch, example config indent ([ac48a4f](https://github.com/bcit-tlu/haproxy-operator/commit/ac48a4f3df16b9b8f144296a1c30bfa00cf75dc8))
* store status-message in annotations, skip failed-hash retry loop, add tests ([4a23d60](https://github.com/bcit-tlu/haproxy-operator/commit/4a23d603d22487938518d7694aa8a26da3343189))
* use modern httpchk syntax for HAProxy 2.2+ in dev examples ([5954e82](https://github.com/bcit-tlu/haproxy-operator/commit/5954e820ae203788e70f94ef4fb7623fa2f19728))
