## [unreleased]

### 🚀 Features

- The design, the decisions, and the container skeleton ([65ed744](https://github.com/murat-akpinar/OpenBerat/commit/65ed74439e5e57e607b7aae4433474f7b3037956)) — OpenBerat is an identity-aware proxy: Keycloak federates to Active Directory, and a user reaches only the applications their AD group membership allows, through a portal and without a VPN. This commit is the whole design and none of the runtime — eighteen ADRs, the target architecture with its request path and ports, the requirements and the roadmap, alongside the per-container directories whose Dockerfiles are still commented stubs. Phase 1 is a lab that verifies the architecture against a real directory before a line of code is written.
