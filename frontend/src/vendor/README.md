# vendor

Third-party files copied into the repository by hand (ADR-0007: no npm, no
build step, no CDN). Upgrades are manual and visible in the commit.

## alpine.js — Alpine.js **CSP build**, v3.17.1, MIT

| | |
|---|---|
| Package | `@alpinejs/csp@3.17.1`, file `dist/cdn.min.js` |
| Source | `https://registry.npmjs.org/@alpinejs/csp/-/csp-3.17.1.tgz` |
| npm integrity | `sha512-HDrY0ZxvJWSmeUYqtHVSsitaqy1es3VDCNodPpdQRX4nHhHiRoeib+rOzRFFStFRD/6x0KmQzJVJ4FCLAI/DUQ==` |
| sha256 as published | `dd45019f9fba2b5edd4cfdc5870df1acb22d918a0ede0d0a0699ae0c866049bf` |
| sha256 of the file here | `e02c921a928c6148783bf817b481de6c976579188a4cefa84b264cae5524bf86` — the published bytes with the MIT banner prepended, and nothing else |

**Why the CSP build and not the standard one.** Measured, not assumed
(`docs/07`, "Alpine.js under `default-src 'self'`"): the standard build loads
under that policy and then evaluates nothing — every binding dies on
`script-src blocked eval`, because it compiles expressions with
`new Function()`. The CSP build parses them instead and raises no violation.
Vendoring the standard build would mean writing `unsafe-eval` into the CSP of
the one host every user opens, which is the opposite of what this product
claims to do. The `frontend` job in CI fails if a file here regains `eval(` or
`new Function`, so a careless upgrade cannot quietly undo that.

**What the parser refuses.** Arrow functions and template literals — nothing
else that was tried. Property paths, comparisons, ternaries, `&&`/`||`, member
calls with arguments, assignment in `x-on`/`x-init`, `x-for` and the magics all
work. Put anything more involved in the `Alpine.data()` object, which is
ordinary JavaScript in an ordinary `.js` file and has no restrictions at all.

**Licence.** MIT, © Caleb Porzio and contributors. The published package ships
no licence file and the minified build carries no banner, so the **notice is
prepended here** — the file is served to every browser that opens the portal,
and MIT asks for the notice to travel with the copy (ADR-0013). That banner is
the only difference between this file and the published one, which is why both
checksums are above: verify the tarball against the first, add the banner, and
the result must be the second.

To upgrade: bump the version in the URL above, verify the tarball against the
`integrity` field npm returns for it, replace the file and put the banner back
with the new version in it — the CI check and the `docs/07` finding both still
apply, and CI also fails if the banner goes missing.
