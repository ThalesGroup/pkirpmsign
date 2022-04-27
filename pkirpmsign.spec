Name:           pkirpmsign
Version:        1.0.1
Release:        1%{?dist}
Summary:        Signs rpm with xmldsig format and key/cert from pki

License:        GPL
Source0:        %{_topdir}/pkirpmsign.tar.gz

BuildRequires:  xmlsec1-devel xmlsec1-openssl-devel libxml2-devel make gettext

%description
Signs rpm with xmldsig format and key/cert from pki

%prep
%setup -qc

%build
make

%install
install -m 755 -d $RPM_BUILD_ROOT/%{_bindir}
mkdir -p %{buildroot}/usr/bin/
mkdir -p %{buildroot}/usr/share/locale/fr/LC_MESSAGES/
install -m 755 pkirpmsign %{buildroot}/usr/bin/pkirpmsign
install -m 755 pkirpmverify %{buildroot}/usr/bin/pkirpmverify
install -m 644 po/fr/pkirpmsign.mo %{buildroot}/usr/share/locale/fr/LC_MESSAGES/pkirpmsign.mo

%files
%doc README.md TODO
/usr/bin/pkirpmsign
/usr/bin/pkirpmverify
/usr/share/locale/fr/LC_MESSAGES/pkirpmsign.mo

%changelog
* Thu Mar 31 2022 theo <theophile.arrivet@free.fr>
- 
