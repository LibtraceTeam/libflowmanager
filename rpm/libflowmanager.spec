Name:           libflowmanager
Version:        3.0.0
Release:        3%{?dist}
Summary:        C/C++ Library for performing flow-based network traffic analysis

License:        LGPLv3
URL:            https://github.com/wanduow/libflowmanager
Source0:        https://github.com/wanduow/libflowmanager/archive/%{version}.tar.gz

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: libtrace4-devel

Provides: libflowmanager

%description
libflowmanager is a library that assists in performing flow-based
network traffic analysis on conventional network packet captures. The
library automates the process of matching packets to their corresponding
flows, maintains a table of all active flows and expires flows after a
suitable period of inactivity.

libflowmanager is developed by the WAND Network Research Group at Waikato
University in New Zealand.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%prep
%setup -q -n libflowmanager-%{version}

%build
%configure --disable-static
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%license COPYING
%{_libdir}/libflowmanager.so.*

%files devel
%{_includedir}/libflowmanager*
%{_includedir}/tcp_reorder.h
%{_libdir}/libflowmanager.so

%changelog
* Mon Mar 29 2021 Shane Alcock <shane.alcock@waikato.ac.nz> - 3.0.0-3
- Repackage to link against latest libtrace release

* Thu Oct 29 2020 Shane Alcock <shane.alcock@waikato.ac.nz> - 3.0.0-1
- First libflowmanager RPM package
