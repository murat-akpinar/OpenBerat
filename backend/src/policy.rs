// PDP — the authorisation decision. The heart of the project.
// Decision order and rules: docs/05-authz-model.md
// Stays a pure function (no DB access, inputs -> decision); its tests live here.
// URI normalisation belongs here too: matching on the raw path lets a request
// like /%61dmin/ skip a deny rule (docs/05 "Path normalisation").
