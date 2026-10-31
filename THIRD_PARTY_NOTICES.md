# Third-party software

## sing-box

`FimaVPN.exe` bundles the unmodified `sing-box.exe` (and `libcronet.dll`) release **v1.13.14** from
<https://github.com/SagerNet/sing-box>, started as a separate process. sing-box is
Copyright (C) 2022 by nekohasekai and is licensed under the GNU General Public License v3.0 or later,
with the additional terms stated in its license file (bundled inside the executable as `core/LICENSE`, and available at
<https://github.com/SagerNet/sing-box/blob/v1.13.14/LICENSE>).

Corresponding source code for the bundled version:
<https://github.com/SagerNet/sing-box/tree/v1.13.14>

The release binaries are the official ones from
<https://github.com/SagerNet/sing-box/releases/tag/v1.13.14>; `build.ps1` downloads the same files.

## Xray-core

The program also bundles the unmodified `xray` (`xray.exe` on Windows) release **v26.10.29** from
<https://github.com/XTLS/Xray-core>, started as a separate process only for servers the sing-box core cannot run
(XHTTP, mKCP and the like). Xray-core is licensed under the Mozilla Public License 2.0 (bundled as `core/XRAY-LICENSE`,
available at <https://github.com/XTLS/Xray-core/blob/main/LICENSE>). Its source code is at
<https://github.com/XTLS/Xray-core/tree/v26.10.29>. The release workflow downloads the official binaries and checks
them against the checksums published with the release.

## Rule sets

`core/geoip-ru.srs` and `core/geosite-ru.srs` are sing-box rule sets published at
<https://github.com/SagerNet/sing-geoip> and <https://github.com/SagerNet/sing-geosite>
(branch `rule-set`, mirrored by jsDelivr). See those repositories for their terms. The app refreshes them weekly
into `%APPDATA%\FimaVPN\rules`.
