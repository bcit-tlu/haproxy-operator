# Changelog

## [0.4.0](https://github.com/bcit-tlu/haproxy-operator/compare/v0.3.0...v0.4.0) (2026-09-24)


### Features

* **operator:** typed dataplane errors, safe retry, VSO contract, readiness ([#21](https://github.com/bcit-tlu/haproxy-operator/issues/21)) ([b65c683](https://github.com/bcit-tlu/haproxy-operator/commit/b65c683f7248804d1a49b7b43772b87bd939e7d2))

## [0.3.0](https://github.com/bcit-tlu/haproxy-operator/compare/v0.2.0...v0.3.0) (2026-04-21)


### Features

* **ci:** unify image, chart, and release versions under release-please lineage ([#10](https://github.com/bcit-tlu/haproxy-operator/issues/10)) ([db7fcb5](https://github.com/bcit-tlu/haproxy-operator/commit/db7fcb5d48a63e88ef82a72ca4a98a2d23a518ab))
* scaffold haproxy-operator with Flux GitOps, SPIRE mTLS, and VSO integration ([7e80e93](https://github.com/bcit-tlu/haproxy-operator/commit/7e80e935b0ef2c450f562969e133b0e7149ad2e1))


### Bug Fixes

* address Devin Review findings — SPIRE lifecycle, double validation, dynamic RootCAs, unit tests ([4985dc0](https://github.com/bcit-tlu/haproxy-operator/commit/4985dc00b42410194f5440949ee438b06e4ac429))
* **ci:** unblock image job on private-repo SARIF upload ([#11](https://github.com/bcit-tlu/haproxy-operator/issues/11)) ([8e40960](https://github.com/bcit-tlu/haproxy-operator/commit/8e409607fde6acb4a35f635a02d70983a1d89943))
* clear LastFailedHashAnnotation on successful apply ([0616620](https://github.com/bcit-tlu/haproxy-operator/commit/06166202ca8c472ba69125b8b5ce4593c9b989bd))
* retry client init on failure, context-aware waitForReady, deduplicate events ([f66f835](https://github.com/bcit-tlu/haproxy-operator/commit/f66f835116c4647aca056e4ce7b55b7729d67112))
* SPIRE source leak on client error, atomic file watch, example config indent ([ac48a4f](https://github.com/bcit-tlu/haproxy-operator/commit/ac48a4f3df16b9b8f144296a1c30bfa00cf75dc8))
* store status-message in annotations, skip failed-hash retry loop, add tests ([4a23d60](https://github.com/bcit-tlu/haproxy-operator/commit/4a23d603d22487938518d7694aa8a26da3343189))
* use modern httpchk syntax for HAProxy 2.2+ in dev examples ([5954e82](https://github.com/bcit-tlu/haproxy-operator/commit/5954e820ae203788e70f94ef4fb7623fa2f19728))

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
