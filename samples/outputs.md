# Sample query outputs (full text)

Generated 2026-11-11 against the 2026-11-05 snapshot. Same model (`vertex_ai/gemini-3.5-flash`) for both columns.
**No tools** = the message alone, no system prompt, no tools. **PatchWise** = the `/chat` pipeline.

## Query 1

```text
We use urllib3==1.26.17. Does CVE-2023-45803 mean we have to move to v2?
```

### No tools (9.6 s)

**No, you do not have to upgrade to v2 (urllib3 2.x) to fix CVE-2023-45803.** 

The maintainers of `urllib3` backported the fix for this vulnerability to the 1.26.x branch. 

### Your Options:

#### Option 1: Stay on v1 (Easiest)
You can resolve this vulnerability by upgrading to **`urllib3>=1.26.18`**. 

To get the latest security patches for the 1.x branch, you should run:
```bash
pip install --upgrade "urllib3>=1.26.18,<2"
```
*(Note: As of today, the latest version in the 1.x branch is `1.26.20`, which also fixes subsequent vulnerabilities like CVE-2024-37891).*

#### Option 2: Upgrade to v2
If you choose to upgrade to the modern v2 branch, you must upgrade to **`urllib3>=2.0.7`** (ideally the latest 2.x version) to be safe from this CVE. 

*Warning:* Upgrading to v2 requires Python 3.7+ and OpenSSL 1.1.1+, and it contains breaking changes that might affect your codebase or other dependencies.

---

### What was CVE-2023-45803?
This vulnerability causes `urllib3` to fail to remove the HTTP request body when a request is redirected from a POST (or other method containing a body) to a GET request via a `303 See Other` redirect. This can lead to sensitive data (like credentials or API payloads) being leaked to the destination of the redirect. 

### Recommendation
If your application or its dependencies are not yet ready for `urllib3` v2, simply **upgrade to the latest `1.26.x` version** (currently `1.26.20`). This will fix CVE-2023-45803 without introducing breaking changes.

### PatchWise (32.4 s, 10 tool calls; agents: lead, researcher:urllib3, writer)

No, you do not have to upgrade to v2 to fix CVE-2023-45803, as upgrading to 1.26.18 resolves this issue on the 1.26.x line [1](https://pypi.org/project/urllib3/1.26.18/). However, your pin is affected by 9 total advisories, and the smallest full fix to resolve all of them is a major upgrade to version 2.8.0 [2](https://pypi.org/project/urllib3/2.8.0/).

### urllib3==1.26.17

* **Affected**: Affected by 9 advisories, including CVE-2023-45803 (GHSA-g4mx-q9vg-27p4) [3](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4).
* **Smallest safe upgrade**: This requires a major jump to 2.8.0 to fully clear all advisories [2](https://pypi.org/project/urllib3/2.8.0/). If you remain on your current line, upgrading to 1.26.18 resolves CVE-2023-45803 [1](https://pypi.org/project/urllib3/1.26.18/), and upgrading to 1.26.19 is the best same-line partial fix (clearing 2 advisories and leaving 7 remaining) [4](https://pypi.org/project/urllib3/1.26.19/).
* **What changes**: 
  * urllib3 will strip the body from HTTP requests that change their method to GET following a 303 "See Other" redirect response [5](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L664-L667). (On the 2.x line, this change was introduced in 2.0.7 [3](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4)).
  * Upgrading to 1.26.19 automatically strips `Proxy-Authorization` headers during redirects to a different host [6](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L658-L662).
  * Version 1.26.19 correctly handles OpenSSL 3.2.0 errors that occur when an HTTP proxy is misconfigured as HTTPS [6](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L658-L662).
* **Check before upgrading**: 
  * Verify that your application does not rely on retaining request bodies during 303 redirects [5](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L664-L667).
  * Confirm you do not depend on sending `Proxy-Authorization` headers across different origins during redirects, or explicitly configure `Retry.remove_headers_on_redirect` to allow keeping them [6](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L658-L662).
* **Can't tell from the data**: Whether your application actually makes requests that encounter 303 redirects or relies on cross-origin proxy credentials.

**Sources**
1. [urllib3 1.26.18: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/urllib3/1.26.18/)
2. [urllib3 2.8.0: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/urllib3/2.8.0/)
3. [GHSA-g4mx-q9vg-27p4: urllib3's request body not stripped after redirect from 303 status changes request method to GET](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4)
4. [urllib3 1.26.19: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/urllib3/1.26.19/)
5. [urllib3 1.26.18 release notes](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L664-L667)
6. [urllib3 1.26.19 release notes](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L658-L662)

## Query 2

```text
We're on django==4.2.10 and can't do a major upgrade this sprint. What's the smallest upgrade that fixes the known security advisories, and what changes?
```

### No tools (15.3 s)

To fix all currently known security advisories without performing a major upgrade, you should upgrade to the latest patch release in the 4.2 LTS (Long Term Support) series: **`django==4.2.19`** (released February 5, 2025).

Because Django strictly follows semantic versioning, upgrading from `4.2.10` to `4.2.19` is a **drop-in, backward-compatible patch upgrade**. It contains zero breaking API changes, requires no database migrations, and is extremely low-risk for a single-sprint deployment.

---

### What Changes Between 4.2.10 and 4.2.19?

By making this jump, you will resolve several security vulnerabilities (CVEs) and get a handful of minor, stable bug fixes. Here is a summary of the security advisories you will patch:

#### 1. Directory Traversal Vulnerabilities (High/Moderate Severity)
*   **CVE-2025-24933 (Fixed in 4.2.19):** A directory traversal vulnerability in `django.views.static.serve` when using specific file-path structures on Windows.
*   **CVE-2024-39330 (Fixed in 4.2.14):** A directory traversal vulnerability in `Storage.save()` where maliciously crafted filenames could allow writing files outside the designated media root directory.

#### 2. SQL Injection Vulnerability (High Severity)
*   **CVE-2024-53907 (Fixed in 4.2.17):** A potential SQL injection vulnerability in `QuerySet.order_by()` when users control input to database functions passed directly to the order-by clause.

#### 3. Denial of Service (DoS) Vulnerabilities (Moderate Severity)
The remaining CVEs resolved in these patches are primarily Regular Expression Denial of Service (ReDoS) or memory exhaustion vectors:
*   **CVE-2025-23011 (Fixed in 4.2.18):** DoS in `django.utils.cache.patch_vary_headers` via maliciously formatted `Vary` headers.
*   **CVE-2024-45230 & CVE-2024-45231 (Fixed in 4.2.16):** DoS via URI parsing in `urlize` and localization/translation components.
*   **CVE-2024-41989, CVE-2024-41990, CVE-2024-41991 (Fixed in 4.2.15):** DoS vectors in `floatformat`, `urlize`, and translation scripts.
*   **CVE-2024-38875 & CVE-2024-39614 (Fixed in 4.2.14):** DoS via `urlize` parsing and translation features.
*   **CVE-2024-27351 & CVE-2024-24680 (Fixed in 4.2.11):** ReDoS in `urlize` and a crash/DoS in the `intcomma` template filter when handling very large numbers.

---

### Action Plan for Your Sprint

To complete this upgrade safely and quickly:

1.  **Update your dependency file:**
    Change your requirement in `requirements.txt`, `Pipfile`, or `pyproject.toml` to:
    ```text
    Django==4.2.19
    ```
2.  **Install the update:**
    ```bash
    pip install -U django==4.2.19
    ```
3.  **Run your test suite:**
    Because this is a minor patch upgrade, your tests should pass immediately with zero modifications.
4.  **Deploy:**
    Since there are no database migrations associated with Django's internal patch releases, this can be deployed seamlessly.

### PatchWise (37.8 s, 11 tool calls; agents: lead, researcher:django, writer)

To address your security concerns without performing a major upgrade this sprint, you can upgrade to Django 4.2.30. This patch upgrade resolves 37 of the 45 advisories affecting your current version, though 8 advisories will remain unresolved until you can perform a major upgrade [1](https://pypi.org/project/django/4.2.30/).

### django==4.2.10

* **Affected**: Yes, affected by 45 advisories [2](https://pypi.org/project/django/4.2.10/).
* **Smallest safe upgrade**: Upgrading to 4.2.30 (patch jump) is a partial fix that clears 37 advisories and leaves 8 remaining [1](https://pypi.org/project/django/4.2.30/). A full fix requires upgrading to 5.2.17 (major jump) [3](https://pypi.org/project/django/5.2.17/). The remaining 8 advisories—such as `GHSA-923m-gv2p-w5qp` (Vary header exposure) and `GHSA-h7pc-vwp9-298g` (cookie salt collision)—have no fix on the 4.2 line in the snapshot [1](https://pypi.org/project/django/4.2.30/). The earliest fix for these is on 5.2.15 (part of the 5.2.17 target) [3](https://pypi.org/project/django/5.2.17/) [4](https://osv.dev/vulnerability/GHSA-923m-gv2p-w5qp).
* **What changes**:
  * **Directory extraction**: `django.utils.archive.extract()` prevents partial directory traversal by blocking paths sharing a common prefix with the target directory [5](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.25.txt?plain=1#L22-L25).
  * **File permission handling**: Directory creation in file-system storage and file-based cache backends now uses `os.chmod` instead of relying on the process `umask`, avoiding multi-threaded permission errors [6](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.29.txt?plain=1#L35-L45).
  * **Language parsing limit**: To prevent DoS, `get_supported_language_variant()` now parses language codes to a maximum of 500 characters, raising a `ValueError` if exceeded [7](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.14.txt?plain=1#L39-L49).
  * **Scheme detection logic**: `URLField.to_python()` skips slow Windows Unicode normalization, which changes how inner whitespace and control characters are handled [8](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.29.txt?plain=1#L13-L30).
* **Check before upgrading**:
  * **Custom URL validators**: Ensure custom URL validators do not rely on `URLField.to_python()` performing Unicode normalization or stripping embedded newlines or control characters [8](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.29.txt?plain=1#L13-L30).
  * **Language codes**: Ensure the application does not process language codes longer than 500 characters [7](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.14.txt?plain=1#L39-L49).
* **Can't tell from the data**: Whether your application uses custom URL validators, parses extremely long language codes, or uses the affected features like GeoDjango or `MultiPartParser` [1](https://pypi.org/project/django/4.2.30/).

**Sources**
1. [django 4.2.30: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/django/4.2.30/)
2. [django 4.2.10: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/django/4.2.10/)
3. [django 5.2.17: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/django/5.2.17/)
4. [GHSA-923m-gv2p-w5qp: Django: has_vary_header may expose cached responses when Vary values contain whitespace](https://osv.dev/vulnerability/GHSA-923m-gv2p-w5qp)
5. [django 4.2.25 release notes: CVE-2025-59682: Potential partial directory-traversal via ``archive.extract()``](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.25.txt?plain=1#L22-L25)
6. [django 4.2.29 release notes: CVE-2026-25674: Potential incorrect permissions on newly created file system objects](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.29.txt?plain=1#L35-L45)
7. [django 4.2.14 release notes: CVE-2024-39614: Potential denial-of-service vulnerability in ``get_supported_language_variant()``](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.14.txt?plain=1#L39-L49)
8. [django 4.2.29 release notes: CVE-2026-25673: Potential denial-of-service vulnerability in ``URLField`` via Unicode normalization on Windows](https://github.com/django/django/blob/b3997c604720ff061e9d3588c86a9bf7ca07fa32/docs/releases/4.2.29.txt?plain=1#L13-L30)

## Query 3

```text
# requirements.txt
starlette==0.36.0
aiohttp==3.10.2
urllib3==2.2.1
```

### No tools (8.0 s)

Based on the `requirements.txt` file you provided, here is a quick **security and compatibility audit** of these specific versions, along with recommendations for updates.

---

### ⚠️ Security Audit & Vulnerability Alert

Two of the packages in your list have known security vulnerabilities in these specific versions:

#### 1. `urllib3==2.2.1` (Vulnerable)
* **Vulnerability:** **CVE-2024-37891** (Severity: Medium - 6.5)
* **Issue:** A proxy-authorization header leak. When using a proxy, `urllib3` fails to strip the `Proxy-Authorization` header when redirecting to a different host.
* **Remediation:** Upgrade to **`urllib3>=2.2.2`** (the current latest is `2.2.3`).

#### 2. `aiohttp==3.10.2` (Vulnerable)
* **Vulnerability:** **CVE-2024-52304** / **CVE-2024-52303** (Severity: High)
* **Issue:** HTTP request smuggling and improper validation of request headers, which can lead to security bypasses or cache poisoning.
* **Remediation:** Upgrade to **`aiohttp>=3.10.11`** (or the newer `3.11.x` branch).

#### 3. `starlette==0.36.0` (Safe)
* **Status:** This version is generally safe, but Starlette is currently on `0.41.x`+. Upgrading is recommended for performance improvements and compatibility with newer Python versions.

---

### 🛡️ Recommended `requirements.txt` (Secure & Updated)

To fix the security vulnerabilities while maintaining maximum compatibility with your existing code, you should update your `requirements.txt` to the following patched versions:

```text
starlette>=0.36.0,<0.42.0
aiohttp>=3.10.11,<4.0.0
urllib3>=2.2.2,<3.0.0
```

*Using `>=` (greater than or equal to) with `<` (less than major version) ensures you get security patches automatically without breaking your code with major breaking changes.*

### How to install/update:
Save the updated file and run:
```bash
pip install --upgrade -r requirements.txt
```

### PatchWise (64.9 s, 33 tool calls; agents: lead, researcher:aiohttp, researcher:starlette, researcher:urllib3, writer)

All three packages pinned in your requirements file are affected by security vulnerabilities. Upgrading starlette to 1.3.1 (major jump), aiohttp to 3.14.4 (minor jump), and urllib3 to 2.8.0 (minor jump) will resolve all 58 detected vulnerabilities.

### starlette==0.36.0

*   **Affected**: Affected by 7 advisories [1](https://pypi.org/project/starlette/0.36.0/).
*   **Smallest safe upgrade**: Upgrading to `1.3.1` (major jump) [2](https://pypi.org/project/starlette/1.3.1/). There is no fix on the 0.36 or 0.37 release lines in the snapshot [1](https://pypi.org/project/starlette/0.36.0/).
*   **What changes**: Resolves multiple Denial of Service vectors triggered by multipart/form-data parsing and silent bypassing of URL-encoded form limits [3](https://osv.dev/vulnerability/GHSA-f96h-pmfr-66vw) [4](https://osv.dev/vulnerability/GHSA-2c2j-9gv5-cj73) [5](https://osv.dev/vulnerability/GHSA-82w8-qh3p-5jfq). Fixes missing validation of request path and Host headers that allows poisoning of `request.url.path` and `request.url.hostname` [6](https://osv.dev/vulnerability/GHSA-86qp-5c8j-p5mr) [7](https://osv.dev/vulnerability/GHSA-jp82-jpqv-5vv3). Resolves SSRF and credential theft caused by UNC paths in Windows `StaticFiles` [8](https://osv.dev/vulnerability/GHSA-wqp7-x3pw-xc5r). Prevents arbitrary HTTP methods from being dispatched to `HTTPEndpoint` [9](https://osv.dev/vulnerability/GHSA-x746-7m8f-x49c). The `methods` parameter type changed from `list[str]` to `Collection[str]` in 0.47.0 [10](https://github.com/Kludex/starlette/blob/0f08970e5cce0aec4fc1cea7447c262d741795eb/docs/release-notes.md?plain=1#L453-L456). Deprecated `allow_redirects` and `app` arguments were removed from `TestClient` [11](https://github.com/Kludex/starlette/blob/0f08970e5cce0aec4fc1cea7447c262d741795eb/docs/release-notes.md?plain=1#L537-L537) [12](https://github.com/Kludex/starlette/blob/0f08970e5cce0aec4fc1cea7447c262d741795eb/docs/release-notes.md?plain=1#L685-L686).
*   **Check before upgrading**: Update `TestClient` calls to remove the deprecated `app` argument [12](https://github.com/Kludex/starlette/blob/0f08970e5cce0aec4fc1cea7447c262d741795eb/docs/release-notes.md?plain=1#L685-L686) and the `allow_redirects` parameter [11](https://github.com/Kludex/starlette/blob/0f08970e5cce0aec4fc1cea7447c262d741795eb/docs/release-notes.md?plain=1#L537-L537). Watch for `DeprecationWarning` regarding `TestClient(timeout=...)` introduced in 0.46.0 [13](https://github.com/Kludex/starlette/blob/0f08970e5cce0aec4fc1cea7447c262d741795eb/docs/release-notes.md?plain=1#L493-L493).
*   **Can't tell from the data**: Whether the application runs on Windows [8](https://osv.dev/vulnerability/GHSA-wqp7-x3pw-xc5r) or implements affected `HTTPEndpoint` routes [9](https://osv.dev/vulnerability/GHSA-x746-7m8f-x49c).

### aiohttp==3.10.2

*   **Affected**: Affected by 42 advisories [14](https://pypi.org/project/aiohttp/3.10.2/).
*   **Smallest safe upgrade**: Upgrading to `3.14.4` (minor jump) [15](https://pypi.org/project/aiohttp/3.14.4/). Upgrading to patch version `3.10.11` is a partial fix on the same line that clears only 1 advisory and leaves 41 vulnerabilities remaining [16](https://pypi.org/project/aiohttp/3.10.11/).
*   **What changes**: Upgrading to `3.10.11` fixes request smuggling via incorrect chunk extension parsing in the pure Python parser [17](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L4316-L4362) [18](https://osv.dev/vulnerability/GHSA-8495-4g3g-x7pr). Moving to `3.14.4` comprehensively fixes request smuggling across chunked trailers, pure-Python parsing, and WebSocket upgrades [19](https://osv.dev/vulnerability/GHSA-9548-qrrj-x5pj) [20](https://osv.dev/vulnerability/GHSA-pqxq-w44r-73xw) [21](https://osv.dev/vulnerability/GHSA-mfx4-hv73-q22v). It also resolves local file read and UNC SSRF on Windows static handlers [22](https://osv.dev/vulnerability/GHSA-p998-jp59-783m), auto-decompress zip bombs [23](https://osv.dev/vulnerability/GHSA-6mq8-rvhq-8wgg), multipart CRLF/header size bypasses [24](https://osv.dev/vulnerability/GHSA-2vrm-gr82-f7m5) [25](https://osv.dev/vulnerability/GHSA-m5qp-6w8w-w647), and multiple memory and CPU DoS vectors [26](https://osv.dev/vulnerability/GHSA-3wq7-rqq7-wx6j) [27](https://osv.dev/vulnerability/GHSA-hcc4-c3v8-rx92).
*   **Check before upgrading**: The minimum required `yarl` version is bumped to `1.12.0` and then `1.25.1` [28](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L4882-L4896) [29](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L506-L541). The minimum `Brotli`/`brotlicffi` dependency is `1.2`, which introduces a new 32MiB decompression limit [30](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L2165-L2170). Default `ClientTimeout` now includes a 30-second `sock_connect` timeout [31](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L4493-L4499). Form fields on `post()` are capped at 1000 by default, returning a `413` status code if exceeded [32](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L52-L87). `aiohttp.BasicAuth` and parameters `auth`/`proxy_auth` are deprecated in favor of `encode_basic_auth` [33](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L1488-L1506). Using `aiohttp.pytest_plugin` is deprecated in favor of `pytest-aiohttp` [33](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L1488-L1506). `Set-Cookie` parsing is restricted to create exactly one cookie per field [29](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L506-L541) [34](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L377-L420). Subclassed `BaseConnector.connect` must define `ceil_timeout` [35](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L4370-L4376).
*   **Can't tell from the data**: Whether your application relies on custom stream writers, custom connectors, or forms containing more than 1000 fields.

### urllib3==2.2.1

*   **Affected**: Affected by 9 advisories [36](https://pypi.org/project/urllib3/2.2.1/).
*   **Smallest safe upgrade**: Upgrading to `2.8.0` (minor jump) [37](https://pypi.org/project/urllib3/2.8.0/). This is a full fix on the same major line [37](https://pypi.org/project/urllib3/2.8.0/).
*   **What changes**: Upgrading to version `2.2.2` only resolves the stripping of the `Proxy-Authorization` header during cross-origin redirects [38](https://pypi.org/project/urllib3/2.2.2/) [39](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf), leaving 8 vulnerabilities unaddressed. Upgrading to `2.8.0` resolves high-severity issues where TLS configurations for HTTPS proxies were ignored [37](https://pypi.org/project/urllib3/2.8.0/) [40](https://osv.dev/vulnerability/GHSA-8988-9cw3-xx77), and unbounded chunk buffering in `stream()` [37](https://pypi.org/project/urllib3/2.8.0/) [41](https://osv.dev/vulnerability/GHSA-vxq7-64xx-v4gw). Chains in the `Content-Encoding` header are now limited to 5 links to prevent decompression bomb DoS [42](https://pypi.org/project/urllib3/2.6.0/) [43](https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53). Deprecated features now emit visible `FutureWarning` alerts [44](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L184-L193).
*   **Check before upgrading**: Destination TLS certificates and overrides no longer apply to HTTPS forwarding proxy connections; you must configure certificates in `proxy_ssl_context` [45](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L7-L27). Support has been dropped for Python 3.8 [46](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L379-L379), Python 3.9 [44](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L184-L193), PyPy3.8 and PyPy3.9 [47](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L417-L418), and PyPy3.10 [44](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L184-L193). If using an environment-level Brotli dependency instead of the official extra, upgrade it to Brotli >= 1.2.0 [48](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L255-L274).
*   **Can't tell from the data**: Whether your application uses the affected streaming APIs, cross-origin redirects, or specific HTTPS forwarding proxies.

---

### Not checked
There were no unpinned, unknown, or uncovered packages provided in the input requirements list.

Please note that a package not being checked does NOT mean it is safe. The PatchWise snapshot only covers django, urllib3, pillow, aiohttp, starlette, and cryptography. We suggest checking any other project dependencies using osv.dev or pip-audit.

**Sources**
1. [starlette 0.36.0: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/starlette/0.36.0/)
2. [starlette 1.3.1: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/starlette/1.3.1/)
3. [GHSA-f96h-pmfr-66vw: Starlette Denial of service (DoS) via multipart/form-data](https://osv.dev/vulnerability/GHSA-f96h-pmfr-66vw)
4. [GHSA-2c2j-9gv5-cj73: Starlette has possible denial-of-service vector when parsing large files in multipart forms](https://osv.dev/vulnerability/GHSA-2c2j-9gv5-cj73)
5. [GHSA-82w8-qh3p-5jfq: Starlette: request.form() limits silently ignored for application/x-www-form-urlencoded enable DoS](https://osv.dev/vulnerability/GHSA-82w8-qh3p-5jfq)
6. [GHSA-86qp-5c8j-p5mr: Starlette has missing Host header validation that poisons request.url.path, bypassing path-based security checks](https://osv.dev/vulnerability/GHSA-86qp-5c8j-p5mr)
7. [GHSA-jp82-jpqv-5vv3: Starlette: Unvalidated request path concatenated into authority poisons request.url.hostname](https://osv.dev/vulnerability/GHSA-jp82-jpqv-5vv3)
8. [GHSA-wqp7-x3pw-xc5r: Starlette: SSRF and NTLM credential theft via UNC paths in StaticFiles on Windows](https://osv.dev/vulnerability/GHSA-wqp7-x3pw-xc5r)
9. [GHSA-x746-7m8f-x49c: Starlette: Arbitrary HTTP method dispatched to `HTTPEndpoint` attributes via `getattr`](https://osv.dev/vulnerability/GHSA-x746-7m8f-x49c)
10. [starlette 0.47.0 release notes: Changed](https://github.com/Kludex/starlette/blob/0f08970e5cce0aec4fc1cea7447c262d741795eb/docs/release-notes.md?plain=1#L453-L456)
11. [starlette 0.43.0 release notes: Removed](https://github.com/Kludex/starlette/blob/0f08970e5cce0aec4fc1cea7447c262d741795eb/docs/release-notes.md?plain=1#L537-L537)
12. [starlette 0.37.2 release notes: Fixed](https://github.com/Kludex/starlette/blob/0f08970e5cce0aec4fc1cea7447c262d741795eb/docs/release-notes.md?plain=1#L685-L686)
13. [starlette 0.46.0 release notes: Deprecated](https://github.com/Kludex/starlette/blob/0f08970e5cce0aec4fc1cea7447c262d741795eb/docs/release-notes.md?plain=1#L493-L493)
14. [aiohttp 3.10.2: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/aiohttp/3.10.2/)
15. [aiohttp 3.14.4: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/aiohttp/3.14.4/)
16. [aiohttp 3.10.11: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/aiohttp/3.10.11/)
17. [aiohttp 3.10.11 release notes: Bug fixes](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L4316-L4362)
18. [GHSA-8495-4g3g-x7pr: aiohttp allows request smuggling due to incorrect parsing of chunk extensions](https://osv.dev/vulnerability/GHSA-8495-4g3g-x7pr)
19. [GHSA-9548-qrrj-x5pj:  AIOHTTP is vulnerable to HTTP Request/Response Smuggling through incorrect parsing of chunked trailer sections](https://osv.dev/vulnerability/GHSA-9548-qrrj-x5pj)
20. [GHSA-pqxq-w44r-73xw: AIOHTTP: Pure-Python parser request smuggling](https://osv.dev/vulnerability/GHSA-pqxq-w44r-73xw)
21. [GHSA-mfx4-hv73-q22v: AIOHTTP: HTTP request smuggling via WebSocket upgrade](https://osv.dev/vulnerability/GHSA-mfx4-hv73-q22v)
22. [GHSA-p998-jp59-783m: AIOHTTP affected by UNC SSRF/NTLMv2 Credential Theft/Local File Read in static resource handler on Windows](https://osv.dev/vulnerability/GHSA-p998-jp59-783m)
23. [GHSA-6mq8-rvhq-8wgg: AIOHTTP's HTTP Parser auto_decompress feature is vulnerable to zip bomb](https://osv.dev/vulnerability/GHSA-6mq8-rvhq-8wgg)
24. [GHSA-2vrm-gr82-f7m5: AIOHTTP has CRLF injection through multipart part content type header construction](https://osv.dev/vulnerability/GHSA-2vrm-gr82-f7m5)
25. [GHSA-m5qp-6w8w-w647: AIOHTTP has a Multipart Header Size Bypass](https://osv.dev/vulnerability/GHSA-m5qp-6w8w-w647)
26. [GHSA-3wq7-rqq7-wx6j: AIOHTTP has late size enforcement for non-file multipart fields causes memory DoS](https://osv.dev/vulnerability/GHSA-3wq7-rqq7-wx6j)
27. [GHSA-hcc4-c3v8-rx92: AIOHTTP Affected by Denial of Service (DoS) via Unbounded DNS Cache in TCPConnector](https://osv.dev/vulnerability/GHSA-hcc4-c3v8-rx92)
28. [aiohttp 3.10.6 release notes: Removals and backward incompatible breaking changes](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L4882-L4896)
29. [aiohttp 3.14.4 release notes: Removals and backward incompatible breaking changes](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L506-L541)
30. [aiohttp 3.13.3 release notes: Removals and backward incompatible breaking changes](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L2165-L2170)
31. [aiohttp 3.10.9 release notes: Removals and backward incompatible breaking changes](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L4493-L4499)
32. [aiohttp 3.14.4 release notes: Features](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L52-L87)
33. [aiohttp 3.14.0 release notes: Deprecations (removal in next major release)](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L1488-L1506)
34. [aiohttp 3.14.4 release notes: Bug fixes](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L377-L420)
35. [aiohttp 3.10.11 release notes: Removals and backward incompatible breaking changes](https://github.com/aio-libs/aiohttp/blob/e87b8b7870440905fe3a2923f3c72d664e5b21ed/CHANGES.rst?plain=1#L4370-L4376)
36. [urllib3 2.2.1: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/urllib3/2.2.1/)
37. [urllib3 2.8.0: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/urllib3/2.8.0/)
38. [urllib3 2.2.2: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/urllib3/2.2.2/)
39. [GHSA-34jh-p97f-mpxf: urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf)
40. [GHSA-8988-9cw3-xx77: urllib3: HTTPS proxy TLS configuration may be ignored or overridden](https://osv.dev/vulnerability/GHSA-8988-9cw3-xx77)
41. [GHSA-vxq7-64xx-v4gw: urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory](https://osv.dev/vulnerability/GHSA-vxq7-64xx-v4gw)
42. [urllib3 2.6.0: release on PyPI; affected/fixed status computed by PatchWise from OSV advisory ranges](https://pypi.org/project/urllib3/2.6.0/)
43. [GHSA-gm62-xv2j-4w53: urllib3 allows an unbounded number of links in the decompression chain](https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53)
44. [urllib3 2.7.0 release notes: Deprecations and Removals](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L184-L193)
45. [urllib3 2.8.0 release notes: Security](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L7-L27)
46. [urllib3 2.3.0 release notes: Deprecations and Removals](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L379-L379)
47. [urllib3 2.2.3 release notes: Deprecations and Removals](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L417-L418)
48. [urllib3 2.6.0 release notes: Security](https://github.com/urllib3/urllib3/blob/c5347bbd39203d68d7b0e3ffb83ced3e3b4b9109/CHANGES.rst?plain=1#L255-L274)
