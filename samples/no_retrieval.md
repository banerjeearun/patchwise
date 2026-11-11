# Ablation: PatchWise without retrieval (full text)

Generated 2026-11-11. Same pipeline and model, but researchers only get the 4 version tools
(`minimal_safe_version`, `advisories_for`, `is_affected`, `fixes_by_branch`). No `search_docs`,
`release_notes`, `notes_for_advisory`, and no code fallback. Compare with [`outputs.md`](outputs.md).

## Query 1 (132.6 s)

```text
We use urllib3==1.26.17. Does CVE-2023-45803 mean we have to move to v2?
```

No, you do not have to move to v2 to resolve CVE-2023-45803, as upgrading to 1.26.18 or higher on the v1 line fixes this vulnerability [1](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4). However, resolving all 9 security advisories affecting your current version requires a major upgrade to version 2.8.0 [2](https://pypi.org/project/urllib3/2.8.0/).

### urllib3==1.26.17

- **Affected**: Yes, by 9 advisories including CVE-2023-45803.
- **Smallest safe upgrade**: A major jump to 2.8.0 resolves all 9 advisories [2](https://pypi.org/project/urllib3/2.8.0/). A same-line partial upgrade to 1.26.19 (minor jump) clears 2 advisories and leaves 7 remaining [3](https://pypi.org/project/urllib3/1.26.19/).
- **What changes**:
  - Release notes weren't analyzed for this package in this run; try again for details.
  - **CVE-2023-45803 resolved**: Upgrading to 1.26.18+ (or 2.0.7+ in v2) ensures the request body is stripped during 303 redirects that change the request method to GET [1](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4).
  - **Proxy-Authorization header stripping**: Upgrading to 1.26.19+ (or 2.0.7+ in v2) resolves GHSA-34jh-p97f-mpxf by stripping `Proxy-Authorization` headers during cross-origin redirects [4](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf).
- **Check before upgrading**:
  - **v1 to v2 migration**: Resolving all known security advisories requires upgrading to 2.8.0, which is a major version jump and may introduce breaking changes [2](https://pypi.org/project/urllib3/2.8.0/).
  - **Remaining v1 vulnerabilities**: Staying on the v1 line (even on the best partial version, 1.26.19) leaves 7 active security advisories unfixed, such as proxy TLS configuration overrides and decompression vulnerabilities [3](https://pypi.org/project/urllib3/1.26.19/).
- **Can't tell from the data**:
  - Whether your application performs requests involving 303 redirects or cross-origin redirects that would trigger the vulnerable codepaths.

**Sources**
1. [GHSA-g4mx-q9vg-27p4: urllib3's request body not stripped after redirect from 303 status changes request method to GET](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4)
2. [urllib3 2.8.0: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/urllib3/2.8.0/)
3. [urllib3 1.26.19: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/urllib3/1.26.19/)
4. [GHSA-34jh-p97f-mpxf: urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf)

## Query 2 (41.4 s)

```text
We're on django==4.2.10 and can't do a major upgrade this sprint. What's the smallest upgrade that fixes the known security advisories, and what changes?
```

To fully resolve all 45 security advisories affecting your current version of `django==4.2.10`, the smallest upgrade is to `django==5.2.17`, which requires a major version jump [1](https://pypi.org/project/django/4.2.10/). If a major upgrade is not possible this sprint, upgrading to `django==4.2.30` is the best partial fix on your current release line, resolving 37 advisories while leaving 8 remaining [2](https://pypi.org/project/django/4.2.30/).

### django==4.2.10

- **Affected**: 45 advisories affect version 4.2.10 [1](https://pypi.org/project/django/4.2.10/).
- **Smallest safe upgrade**: Upgrading to `5.2.17` is a major jump that fully clears all advisories [1](https://pypi.org/project/django/4.2.10/). The best partial fix on the current 4.2 line is upgrading to `4.2.30`, which resolves 37 advisories and leaves 8 remaining [2](https://pypi.org/project/django/4.2.30/).
- **What changes**:
  - Upgrading to 4.2.30 resolves 37 security advisories, addressing SQL injections, path traversal, user email enumeration, and denial-of-service vulnerabilities [1](https://pypi.org/project/django/4.2.10/)[2](https://pypi.org/project/django/4.2.30/).
  - Moving to 5.2.15 fixes 3 of the remaining 8 advisories: whitespace-based cache exposure [3](https://osv.dev/vulnerability/GHSA-923m-gv2p-w5qp), cookie salt collisions [4](https://osv.dev/vulnerability/GHSA-h7pc-vwp9-298g), and case-sensitive Cache-Control exposure [5](https://osv.dev/vulnerability/GHSA-8cjm-8mp7-r2xf).
  - Moving to 5.2.16 resolves another 3 advisories: private cache exposure under cookie presence [6](https://osv.dev/vulnerability/GHSA-3h9f-r86x-qvjx), GDALRaster heap over-reads [7](https://osv.dev/vulnerability/GHSA-crhf-3pfg-w68w), and DomainNameValidator HTTP header injection [8](https://osv.dev/vulnerability/GHSA-8qcx-xf44-272x).
  - Moving to 5.2.17 fixes the final 2 advisories: GeoDjango geometry DoS [9](https://osv.dev/vulnerability/GHSA-q238-5cxm-5c9h) and spatial lookup file writes/requests [10](https://osv.dev/vulnerability/GHSA-wvqv-fj8w-qmhm).
- **Check before upgrading**:
  - Check if your deployment uses GeoDjango, as parsing spatial geometry and raster bytes features are affected by late-stage vulnerabilities [7](https://osv.dev/vulnerability/GHSA-crhf-3pfg-w68w)[9](https://osv.dev/vulnerability/GHSA-q238-5cxm-5c9h)[10](https://osv.dev/vulnerability/GHSA-wvqv-fj8w-qmhm).
  - Verify cache middleware configurations, as case-sensitive handling and whitespace in Vary headers can leak cached content [3](https://osv.dev/vulnerability/GHSA-923m-gv2p-w5qp)[5](https://osv.dev/vulnerability/GHSA-8cjm-8mp7-r2xf)[6](https://osv.dev/vulnerability/GHSA-3h9f-r86x-qvjx).
- **Can't tell from the data**:
  - Whether your application uses the specific vulnerable components, such as Oracle databases, GeoDjango spatial lookups, or multi-part uploads.
  - Specific API deprecations or removals between versions 4.2.10 and 5.2.17.

**Sources**
1. [django 4.2.10: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/django/4.2.10/)
2. [django 4.2.30: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/django/4.2.30/)
3. [GHSA-923m-gv2p-w5qp: Django: has_vary_header may expose cached responses when Vary values contain whitespace](https://osv.dev/vulnerability/GHSA-923m-gv2p-w5qp)
4. [GHSA-h7pc-vwp9-298g: Django: signed cookies are vulnerable to salt namespace collisions](https://osv.dev/vulnerability/GHSA-h7pc-vwp9-298g)
5. [GHSA-8cjm-8mp7-r2xf: Django: UpdateCacheMiddleware may disclose cached responses due to case-sensitive Cache-Control handling](https://osv.dev/vulnerability/GHSA-8cjm-8mp7-r2xf)
6. [GHSA-3h9f-r86x-qvjx: Django: cache middleware may expose private responses when unrelated request cookies are present](https://osv.dev/vulnerability/GHSA-3h9f-r86x-qvjx)
7. [GHSA-crhf-3pfg-w68w:  Django: GDALRaster may over-read heap memory when constructed from bytes](https://osv.dev/vulnerability/GHSA-crhf-3pfg-w68w)
8. [GHSA-8qcx-xf44-272x: Django: DomainNameValidator permits newline characters that may enable HTTP header injection](https://osv.dev/vulnerability/GHSA-8qcx-xf44-272x)
9. [GHSA-q238-5cxm-5c9h: Django GeoDjango vulnerable to denial of service through deeply nested geometry collections](https://osv.dev/vulnerability/GHSA-q238-5cxm-5c9h)
10. [GHSA-wvqv-fj8w-qmhm: Django GeoDjango spatial lookups allow file writes and outbound requests through GDAL raster parsing](https://osv.dev/vulnerability/GHSA-wvqv-fj8w-qmhm)

## Query 3 (157.7 s)

```text
# requirements.txt
starlette==0.36.0
aiohttp==3.10.2
urllib3==2.2.1
```

This security review covers the dependencies `starlette`, `aiohttp`, and `urllib3`, which are affected by several vulnerabilities. Upgrading these packages to their recommended versions will mitigate multiple risks, including denial-of-service, request smuggling, and potential data disclosure.

### starlette==0.36.0
- **Affected**: 7 advisories [1](https://pypi.org/project/starlette/0.36.0/).
- **Smallest safe upgrade**: A major jump to 1.3.1 [1](https://pypi.org/project/starlette/0.36.0/). There are no closer or same-line partial fixes because multiple vulnerabilities lack backports to prior lines [1](https://pypi.org/project/starlette/0.36.0/).
- **What changes**:
  - Release notes weren't analyzed for this package in this run; try again for details.
  - Multipart form parsing is restricted to mitigate DoS from large files or malformed payloads [2](https://osv.dev/vulnerability/GHSA-f96h-pmfr-66vw) [3](https://osv.dev/vulnerability/GHSA-2c2j-9gv5-cj73).
  - Host header validation is introduced to prevent URL path poisoning [4](https://osv.dev/vulnerability/GHSA-86qp-5c8j-p5mr) and hostname poisoning [5](https://osv.dev/vulnerability/GHSA-jp82-jpqv-5vv3).
  - `HTTPEndpoint` limits method dispatching to block arbitrary attribute execution via `getattr` [6](https://osv.dev/vulnerability/GHSA-x746-7m8f-x49c).
  - `StaticFiles` blocks UNC paths on Windows to prevent SSRF and NTLM theft [7](https://osv.dev/vulnerability/GHSA-wqp7-x3pw-xc5r).
  - Form limit checks are enforced on application/x-www-form-urlencoded payloads [8](https://osv.dev/vulnerability/GHSA-82w8-qh3p-5jfq).
- **Check before upgrading**:
  - Ensure Windows deployments serving `StaticFiles` do not utilize UNC paths [7](https://osv.dev/vulnerability/GHSA-wqp7-x3pw-xc5r).
  - Confirm that custom `HTTPEndpoint` subclasses do not expect to route arbitrary HTTP methods via custom attributes [6](https://osv.dev/vulnerability/GHSA-x746-7m8f-x49c).
- **Can't tell from the data**:
  - Whether your application uses the affected features like `StaticFiles` on Windows, multipart form parsing, or `HTTPEndpoint`.
  - Whether there are non-security breaking changes between 0.36.0 and 1.3.1.

### aiohttp==3.10.2
- **Affected**: 42 advisories.
- **Smallest safe upgrade**: A minor jump to 3.14.4 [9](https://pypi.org/project/aiohttp/3.14.4/). Alternatively, a same-line partial upgrade to 3.10.11 clears 1 advisory, leaving 41 remaining advisories [10](https://pypi.org/project/aiohttp/3.10.11/).
- **What changes**:
  - Release notes weren't analyzed for this package in this run; try again for details.
  - Upgrading to 3.10.11 resolves HTTP request smuggling due to incorrect parsing of chunk extensions [11](https://osv.dev/vulnerability/GHSA-8495-4g3g-x7pr) [10](https://pypi.org/project/aiohttp/3.10.11/).
  - Upgrading to 3.14.4 resolves all 42 vulnerabilities affecting 3.10.2 [9](https://pypi.org/project/aiohttp/3.14.4/).
  - Specific vulnerabilities addressed in 3.14.4 include absolute-form request target scheme spoofing [12](https://osv.dev/vulnerability/GHSA-f9xw-jh8m-3mwq) and multiple instances of excessive or unbounded memory/CPU usage [13](https://osv.dev/vulnerability/GHSA-2g87-pp6c-29x5).
  - Other major vulnerabilities affecting 3.10.2 include request/response smuggling through chunked trailer sections [14](https://osv.dev/vulnerability/GHSA-9548-qrrj-x5pj) and a zip bomb vulnerability in the HTTP parser's `auto_decompress` feature [15](https://osv.dev/vulnerability/GHSA-6mq8-rvhq-8wgg).
- **Check before upgrading**:
  - Review request-handling logic to ensure compatibility with stricter parsers implemented for chunked transfers and absolute-form URI targets [11](https://osv.dev/vulnerability/GHSA-8495-4g3g-x7pr) [12](https://osv.dev/vulnerability/GHSA-f9xw-jh8m-3mwq).
- **Can't tell from the data**:
  - Whether there are specific breaking changes or deprecations when upgrading to 3.14.4.
  - Whether your application code is exposed to specific vulnerable pathways, such as using Windows static file handlers or auto-decompressed payloads.

### urllib3==2.2.1
- **Affected**: 9 advisories.
- **Smallest safe upgrade**: A minor jump to 2.8.0, which is a full fix on the same line [16](https://pypi.org/project/urllib3/2.2.1/).
- **What changes**:
  - Strips the `Proxy-Authorization` header during cross-origin redirects [17](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf).
  - Disables redirects when retries are disabled on `PoolManager` instantiation [18](https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v).
  - Imposes safety limits on decompression-chain links to prevent decompression-bomb attacks [19](https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53).
  - Restricts sensitive headers from being forwarded across origins in proxied low-level redirects [20](https://osv.dev/vulnerability/GHSA-qccp-gfcp-xxvc).
  - Ensures HTTPS proxy TLS configurations are not ignored or overridden, and places limits on chunk-size line buffering in `HTTPResponse.stream()` to prevent unbounded memory usage [21](https://osv.dev/vulnerability/GHSA-8988-9cw3-xx77) [22](https://osv.dev/vulnerability/GHSA-vxq7-64xx-v4gw).
- **Check before upgrading**:
  - Verify compatibility of custom redirect and retry logic in `PoolManager`, as automatic redirects are now strictly coupled to retry configuration [18](https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v).
  - Monitor streaming APIs (`HTTPResponse.stream()` and `read_chunked()`) to ensure the newly introduced buffer limit does not disrupt workflows that consume extremely large chunk-size lines [22](https://osv.dev/vulnerability/GHSA-vxq7-64xx-v4gw).
  - Test HTTPS proxy configurations, as stricter validation of proxy TLS settings may reject invalid configurations that were previously ignored [21](https://osv.dev/vulnerability/GHSA-8988-9cw3-xx77).
- **Can't tell from the data**:
  - Whether your application actually uses vulnerable features like low-level proxied redirects, streaming decompression, or custom HTTPS proxy TLS settings.

**Sources**
1. [starlette 0.36.0: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/starlette/0.36.0/)
2. [GHSA-f96h-pmfr-66vw: Starlette Denial of service (DoS) via multipart/form-data](https://osv.dev/vulnerability/GHSA-f96h-pmfr-66vw)
3. [GHSA-2c2j-9gv5-cj73: Starlette has possible denial-of-service vector when parsing large files in multipart forms](https://osv.dev/vulnerability/GHSA-2c2j-9gv5-cj73)
4. [GHSA-86qp-5c8j-p5mr: Starlette has missing Host header validation that poisons request.url.path, bypassing path-based security checks](https://osv.dev/vulnerability/GHSA-86qp-5c8j-p5mr)
5. [GHSA-jp82-jpqv-5vv3: Starlette: Unvalidated request path concatenated into authority poisons request.url.hostname](https://osv.dev/vulnerability/GHSA-jp82-jpqv-5vv3)
6. [GHSA-x746-7m8f-x49c: Starlette: Arbitrary HTTP method dispatched to `HTTPEndpoint` attributes via `getattr`](https://osv.dev/vulnerability/GHSA-x746-7m8f-x49c)
7. [GHSA-wqp7-x3pw-xc5r: Starlette: SSRF and NTLM credential theft via UNC paths in StaticFiles on Windows](https://osv.dev/vulnerability/GHSA-wqp7-x3pw-xc5r)
8. [GHSA-82w8-qh3p-5jfq: Starlette: request.form() limits silently ignored for application/x-www-form-urlencoded enable DoS](https://osv.dev/vulnerability/GHSA-82w8-qh3p-5jfq)
9. [aiohttp 3.14.4: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/aiohttp/3.14.4/)
10. [aiohttp 3.10.11: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/aiohttp/3.10.11/)
11. [GHSA-8495-4g3g-x7pr: aiohttp allows request smuggling due to incorrect parsing of chunk extensions](https://osv.dev/vulnerability/GHSA-8495-4g3g-x7pr)
12. [GHSA-f9xw-jh8m-3mwq: AIOHTTP: Absolute-form request targets can spoof Request.scheme](https://osv.dev/vulnerability/GHSA-f9xw-jh8m-3mwq)
13. [GHSA-2g87-pp6c-29x5: aiohttp: Multiple instances of excessive or unbounded memory/CPU use](https://osv.dev/vulnerability/GHSA-2g87-pp6c-29x5)
14. [GHSA-9548-qrrj-x5pj:  AIOHTTP is vulnerable to HTTP Request/Response Smuggling through incorrect parsing of chunked trailer sections](https://osv.dev/vulnerability/GHSA-9548-qrrj-x5pj)
15. [GHSA-6mq8-rvhq-8wgg: AIOHTTP's HTTP Parser auto_decompress feature is vulnerable to zip bomb](https://osv.dev/vulnerability/GHSA-6mq8-rvhq-8wgg)
16. [urllib3 2.2.1: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/urllib3/2.2.1/)
17. [GHSA-34jh-p97f-mpxf: urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf)
18. [GHSA-pq67-6m6q-mj2v: urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation](https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v)
19. [GHSA-gm62-xv2j-4w53: urllib3 allows an unbounded number of links in the decompression chain](https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53)
20. [GHSA-qccp-gfcp-xxvc: urllib3: Sensitive headers forwarded across origins in proxied low-level redirects](https://osv.dev/vulnerability/GHSA-qccp-gfcp-xxvc)
21. [GHSA-8988-9cw3-xx77: urllib3: HTTPS proxy TLS configuration may be ignored or overridden](https://osv.dev/vulnerability/GHSA-8988-9cw3-xx77)
22. [GHSA-vxq7-64xx-v4gw: urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory](https://osv.dev/vulnerability/GHSA-vxq7-64xx-v4gw)
