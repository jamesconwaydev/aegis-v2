# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Built by `cargo xtask rpm`, which compiles aegisd and aegisctl first
# and runs rpmbuild with _sourcedir at the repository root and
# aegis_bindir at dist/<arch>. It also defines aegis_version from the
# workspace version in Cargo.toml.

# The binaries come prebuilt from cargo; there's no debuginfo to split.
%global debug_package %{nil}
%global selinuxtype targeted
%{!?aegis_version:%{error:aegis_version is unset; build with cargo xtask rpm}}

Name:           aegis-v2
Version:        %{aegis_version}
Release:        1%{?dist}
Summary:        Runtime threat detection for Rocky Linux, built on eBPF
# Aegis itself, the GPL-2.0-only eBPF object aegisd embeds, then every
# licence of the crates statically linked in (THIRD-PARTY-LICENSES has
# their texts). Refresh it when Cargo.lock changes:
#   cargo tree -p aegisd -p aegisctl -e normal,no-proc-macro \
#     --target x86_64-unknown-linux-gnu --prefix none -f '{l}' | sort -u
License:        (MIT OR Apache-2.0) AND GPL-2.0-only AND Apache-2.0 AND BSD-3-Clause AND CDLA-Permissive-2.0 AND ISC AND MIT AND (Apache-2.0 OR ISC OR MIT) AND (MIT OR Unlicense) AND Zlib
URL:            https://github.com/jamesconwaydev/aegis-v2
ExclusiveArch:  x86_64 aarch64

BuildRequires:  selinux-policy-devel
BuildRequires:  systemd-rpm-macros
Requires:       nftables
Requires:       criu
Requires:       (%{name}-selinux = %{version}-%{release} if selinux-policy-%{selinuxtype})
%{?systemd_requires}

%description
aegisd watches every exec, fork, ptrace, memfd and outbound connect
through eBPF, scores each process for risk, and records an incident
when one crosses the line. aegisctl asks it what it has seen.

%package selinux
Summary:        SELinux policy module for aegisd
License:        MIT OR Apache-2.0
BuildArch:      noarch
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
# What %%selinux_requires_min asks for, without its BuildRequires on
# pkgconfig(systemd), which the build image doesn't carry.
Requires(post): selinux-policy-base >= %{_selinux_policy_version}
Requires(post): libselinux-utils
Requires(post): policycoreutils

%description selinux
Confines aegisd to the aegisd_t domain: the BPF and perf access its
probes need, read access to /proc and to executables, the rpm
database, and its own state, socket and log directories. Outbound
network for the OTLP sink sits behind the aegisd_can_network_connect
boolean, off by default.

%prep

%build
cp %{_sourcedir}/selinux/aegis.{te,fc,if} .
%make_build -f %{_datadir}/selinux/devel/Makefile aegis.pp

%install
install -Dpm 0755 %{aegis_bindir}/aegisd %{buildroot}%{_sbindir}/aegisd
install -Dpm 0755 %{aegis_bindir}/aegisctl %{buildroot}%{_bindir}/aegisctl
install -Dpm 0644 %{_sourcedir}/packaging/aegisd.service \
    %{buildroot}%{_unitdir}/aegisd.service
install -Dpm 0644 %{_sourcedir}/packaging/config.toml \
    %{buildroot}%{_sysconfdir}/aegis-v2/config.toml
install -Dpm 0644 %{_sourcedir}/packaging/allowlist.d/00-default.toml \
    %{buildroot}%{_sysconfdir}/aegis-v2/allowlist.d/00-default.toml
install -dm 0700 %{buildroot}%{_sharedstatedir}/aegis-v2
install -dm 0700 %{buildroot}%{_localstatedir}/log/aegis-v2
install -Dpm 0644 aegis.pp \
    %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/aegis.pp
install -Dpm 0644 -t %{buildroot}%{_licensedir}/%{name} \
    %{_sourcedir}/LICENSE-APACHE %{_sourcedir}/LICENSE-MIT \
    %{_sourcedir}/LICENSE-GPL-2.0 %{aegis_bindir}/THIRD-PARTY-LICENSES

%post
%systemd_post aegisd.service
# Tells you now, not at first start, if the kernel can't run aegisd.
%{_bindir}/aegisctl preflight || :

%preun
%systemd_preun aegisd.service

%postun
%systemd_postun_with_restart aegisd.service
# On erase, enforce mode's slices outlive the package: stop them, which
# kills any tree still quarantined, since nothing is left to release it.
# Drop its nftables table, and have systemd forget the removed unit.
if [ $1 -eq 0 ]; then
    systemctl stop aegis.slice 2>/dev/null || :
    nft delete table inet aegis 2>/dev/null || :
    systemctl daemon-reload 2>/dev/null || :
fi

# The selinux-policy macros: install or remove the module, then relabel
# whatever its file contexts changed.
%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/aegis.pp

%postun selinux
%selinux_modules_uninstall -s %{selinuxtype} aegis

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}
# A running aegisd only enters aegisd_t on its next start.
systemctl try-restart aegisd.service 2>/dev/null || :

%files
%license %{_licensedir}/%{name}
%{_sbindir}/aegisd
%{_bindir}/aegisctl
%{_unitdir}/aegisd.service
# config.toml may hold an OTLP bearer token.
%dir %attr(0750,root,root) %{_sysconfdir}/aegis-v2
%dir %{_sysconfdir}/aegis-v2/allowlist.d
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/aegis-v2/config.toml
%config(noreplace) %{_sysconfdir}/aegis-v2/allowlist.d/00-default.toml
%dir %attr(0700,root,root) %{_sharedstatedir}/aegis-v2
%dir %attr(0700,root,root) %{_localstatedir}/log/aegis-v2

%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/aegis.pp

%changelog
* Wed Oct 21 2026 James Conway <148910373+jamesconwaydev@users.noreply.github.com> - 0.1.1-1
- List a member that joined at an exec under the image it runs.
- Record signals by their weight key, not a Rust debug string.
- Update rustls-webpki and webpki-roots (RUSTSEC-2026-0381, -0382).

* Mon Oct 19 2026 James Conway <148910373+jamesconwaydev@users.noreply.github.com> - 0.1.0-1
- First package: aegisd, aegisctl, the systemd unit and the SELinux module.
