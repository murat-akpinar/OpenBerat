# vendor

Third-party files copied into the repository by hand (ADR-0007: no npm, no
build step, no CDN). Upgrades are manual and visible in the commit.

## alpine.js — Alpine.js **CSP build**, v3.17.1, MIT

| | |
|---|---|
| Package | `@alpinejs/csp@3.17.1`, file `dist/cdn.min.js` |
| Source | `https://registry.npmjs.org/@alpinejs/csp/-/csp-3.17.1.tgz` |
| npm integrity | `sha512-HDrY0ZxvJWSmeUYqtHVSsitaqy1es3VDCNodPpdQRX4nHhHiRoeib+rOzRFFStFRD/6x0KmQzJVJ4FCLAI/DUQ==` |
| sha256 of this file | `dd45019f9fba2b5edd4cfdc5870df1acb22d918a0ede0d0a0699ae0c866049bf` |

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
no licence file; the text is at
`https://github.com/alpinejs/alpine/blob/main/LICENSE.md`.

To upgrade: bump the version in the URL above, verify the tarball against the
`integrity` field npm returns for it, and replace the file — the CI check and
the `docs/07` finding both still apply.
