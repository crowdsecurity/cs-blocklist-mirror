Name:           crowdsec-blocklist-mirror
Version:        %(echo $VERSION)
Release:        %(echo $PACKAGE_NUMBER)%{?dist}
Summary:      CrowdSec blocklist mirror 

License:        MIT
URL:            https://crowdsec.net
Source0:        https://github.com/crowdsecurity/%{name}/archive/v%(echo $VERSION).tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  git
BuildRequires:  make
%{?fc33:BuildRequires: systemd-rpm-macros}

%define debug_package %{nil}

%description

%define version_number  %(echo $VERSION)
%define releasever  %(echo $RELEASEVER)
%global local_version v%{version_number}-%{releasever}-rpm
%global name crowdsec-blocklist-mirror
%global __mangle_shebangs_exclude_from /usr/bin/env

%prep
%setup -n crowdsec-blocklist-mirror-%{version}

%build
BUILD_VERSION=%{local_version} make
TMP=`mktemp -p /tmp/`
cp config/%{name}.service ${TMP}
BIN=%{_bindir}/%{name} CFG=/etc/crowdsec/bouncers/ envsubst < ${TMP} > config/%{name}.service
rm ${TMP}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin
install -m 755 -D %{name}  %{buildroot}%{_bindir}/%{name}
install -m 600 -D config/%{name}.yaml %{buildroot}/etc/crowdsec/bouncers/%{name}.yaml 
install -m 644 -D config/%{name}.service %{buildroot}%{_unitdir}/%{name}.service

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/bin/%{name}
%{_unitdir}/%{name}.service
%config(noreplace) /etc/crowdsec/bouncers/%{name}.yaml 


%post -p /bin/bash
systemctl daemon-reload

 
%changelog
* Fri Apr 29 2022 Shivam Sandbhor <shivam@crowdsec.net>
- First initial packaging

%preun -p /bin/bash

if [ "$1" == "0" ] ; then
    systemctl stop crowdsec-blocklist-mirror || echo "cannot stop service"
    systemctl disable crowdsec-blocklist-mirror || echo "cannot disable service"
fi



%postun -p /bin/bash

if [ "$1" == "1" ] ; then
    systemctl restart  crowdsec-blocklist-mirror || echo "cannot restart service"
elif [ "$1" == "0" ] ; then
    systemctl stop crowdsec-blocklist-mirror
    systemctl disable crowdsec-blocklist-mirror
fi