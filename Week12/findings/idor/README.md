# Insecure Direct Object Reference (Unauthenticated Applicant Record Access)

| Field | Value |
|---|---|
| **Severity** | High (CVSS v3.1: 7.5) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **WSTG** | WSTG-ATHZ-04 (Testing for Insecure Direct Object References) |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application) |
| **CWE** | CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-200 (Exposure of Sensitive Information) |
| **Affected endpoint** | `GET /viewform.php`, parameter `id` |
| **Authentication** | None required (confirmed unauthenticated) |

## Summary

The `viewform.php` endpoint returns an applicant's full admission record based on the `id` parameter, and it performs no authorization check on the request. Although the page is linked only from the administrator console, it serves the record to any request, including requests with no session at all. Because the applicant identifiers are sequential and predictable (for example `CUTM00003`, `CUTM00010`), an unauthenticated attacker can change the `id` value to read any applicant's personal data and can enumerate the entire applicant population.

## Reproduction

### 1. Identify the object reference

Within the administrator console, selecting an applicant loads their record at `viewform.php?id=<applicant id>`, for example `viewform.php?id=CUTM00003`. The `id` is the direct object reference, and the identifiers are sequential and zero padded.

### 2. Access the record with no authentication

The tester sent the request in Burp Repeater with the `Cookie` header left empty, so no session was supplied:

```
GET /viewform.php?id=CUTM00003
Cookie:
```

The server responded with `200 OK` and the full, populated applicant form rather than redirecting to a login page. This confirms the endpoint applies no authorization check.

<!-- screenshot: Repeater showing empty Cookie header and 200 OK returning the populated CUTM00003 form -->

### 3. Verify on a second record

To show the reference is not authorization checked for any record, the tester repeated the request unauthenticated with a different identifier:

```
GET /viewform.php?id=CUTM00010
Cookie:
```

The response returned a different applicant's complete record (`CUTM00010`), including name, parents' names and occupations, parents' income, sex, correspondent and permanent addresses, contact numbers, nationality, and academic details.

<!-- screenshot: unauthenticated viewform.php?id=CUTM00010 rendering the full populated record for a different applicant -->

### 4. Enumeration

The identifiers follow the sequential, zero-padded pattern `CUTM00001` through the current maximum. Because access requires no authentication and the IDs are predictable, the complete set of applicant records is enumerable. Testing was limited to two records to demonstrate the flaw without extracting the full population.

## Impact

This is a high-severity information disclosure. Any unauthenticated attacker with network access can retrieve the complete admission record of any applicant by changing a predictable identifier, and can enumerate every applicant in the system. The exposed data includes names, parents' names and occupations, family income, home addresses, contact numbers, and academic results, which is sensitive personal information. The endpoint is read only, so integrity and availability are not directly affected, but the confidentiality impact across the entire applicant population is severe.

## Remediation

- Enforce server-side authorization on `viewform.php`. Require an authenticated session and verify that the requesting account is permitted to view the specific record requested, rather than returning any record keyed only on the `id` value.
- Scope applicant-facing views to the logged-in user's own application, and restrict the full-record view to authorized staff accounts.
- Treat the object reference as untrusted. The authorization decision must depend on the identity and permissions of the requester, not on possession of a valid identifier.
- As defense in depth, replace sequential identifiers with unpredictable values such as UUIDs, though this does not replace the authorization check.

## References

- OWASP WSTG-ATHZ-04: Testing for Insecure Direct Object References
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
