# D-Link DIR-882 A1 Firmware 1.10B02 HNAP1 Allow-listed CGI Unauthenticated Sensitive File Disclosure

## Summary

A missing authentication vulnerability exists in D-Link DIR-882 A1 firmware version 1.10B02. The issue affects the HNAP1 web interface implemented in `/bin/prog.cgi`.

The lighttpd configuration forwards requests under the `/HNAP1/` path to the FastCGI backend `/bin/prog.cgi`. Static analysis shows that the HNAP1 security handler in `prog.cgi` contains an allow-list check for selected download CGI endpoints. The allow-list contains the following CGI names:

- `dlcfg.cgi`
- `dllog.cgi`
- `dlquickvpnsettings.cgi`

When a request path matches one of these allow-listed names, the request can reach the corresponding download handler without requiring a valid authenticated session.

The `dlcfg.cgi` handler returns the device configuration backup file `config.bin`. The `dllog.cgi` handler collects and returns system logs, process information, memory information, and network interface information. The `dlquickvpnsettings.cgi` handler returns the QuickVPN mobile configuration profile if present.

This may allow an unauthenticated remote attacker to access sensitive configuration, log, and VPN profile data from the affected device.

Current status: static analysis confirmed. Runtime confirmation on a physical device or full FastCGI/QEMU emulation environment is pending.

## Affected Product

- Vendor: D-Link
- Product: DIR-882 A1 router firmware
- Affected version: 1.10B02
- Firmware image: `DIR882A1_FW110B02.bin`
- Platform: Embedded Linux, MIPS32 little-endian
- Affected binary:
  - `/bin/prog.cgi`
- Affected interface:
  - `/HNAP1/`
- Affected endpoints:
  - `/HNAP1/dlcfg.cgi`
  - `/HNAP1/dllog.cgi`
  - `/HNAP1/dlquickvpnsettings.cgi`

## Vulnerability Type

- CWE-306: Missing Authentication for Critical Function

## Affected Program Routines

The issue is associated with the following routines in `/bin/prog.cgi`:

- `websSecurityHandler`
- HNAP1 authentication dispatch logic
- HNAP1 download allow-list checker
- `downloadFile`
- `dlcfg.cgi` download handler
- `dllog.cgi` download handler
- `dlquickvpnsettings.cgi` download handler

Relevant code locations observed during static analysis:

- `websSecurityHandler` around `0x424ae0`
- HNAP1 auth dispatch function around `0x423e04`
- HNAP1 allow-list check around `0x423ca8`
- `downloadFile` around `0x42a844`
- `dlcfg.cgi` handler around `0x4297d0`
- `dllog.cgi` handler around `0x42a328`
- `dlquickvpnsettings.cgi` handler around `0x42a500`

Depending on the disassembler's function-boundary recovery, some functions may be displayed with slightly different start addresses, such as `fcn.00423c98`, `fcn.004297c0`, `fcn.0042a318`, or `fcn.0042a4f0`.

## Technical Root Cause

The vulnerable request path is:

```text
/HNAP1/dlcfg.cgi
/HNAP1/dllog.cgi
/HNAP1/dlquickvpnsettings.cgi
    -> lighttpd FastCGI mapping
    -> /bin/prog.cgi
    -> websSecurityHandler()
    -> HNAP1 authentication dispatch logic
    -> HNAP1 download allow-list check
    -> downloadFile()
    -> corresponding download handler
    -> sensitive file returned to the HTTP client
