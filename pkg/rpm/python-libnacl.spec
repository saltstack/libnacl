%if 0%{?fedora} > 12 || 0%{?rhel} > 6
%global with_python3 1
%else

%if 0%{?rhel} == 5
%global with_python26 1
%global pybasever 2.6
%endif

%{!?__python2: %global __python2 /usr/bin/python%{?pybasever}}
%{!?python2_sitearch: %global python2_sitearch %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(1)")}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%endif

%global srcname libnacl

Name:           python-%{srcname}
Version:        1.1.0
Release:        1%{?dist}
Summary:        Python bindings for libsodium/tweetnacl based on ctypes

Group:          Development/Libraries
License:        ASL 2.0
URL:            https://github.com/saltstack/libnacl
Source0:        https://pypi.python.org/packages/source/l/%{srcname}/%{srcname}-%{version}.tar.gz

BuildRoot:      %{_tmppath}/%{srcname}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

BuildRequires:  libsodium
Requires:       libsodium

%if 0%{?with_python26}
BuildRequires:  python26-devel
BuildRequires:  python26-setuptools
%else
BuildRequires:  python-devel
BuildRequires:  python-setuptools
%endif

%if 0%{?with_python3}
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
%endif

%description
This library is used to gain direct access to the functions exposed by Daniel
J. Bernstein's nacl library via libsodium or tweetnacl. It has been constructed
to maintain extensive documentation on how to use nacl as well as being
completely portable. The file in libnacl/__init__.py can be pulled out and
placed directly in any project to give a single file binding to all of nacl.

%if 0%{?with_python3}
%package -n python3-%{srcname}
Summary:  Python bindings for libsodium/tweetnacl based on ctypes
Group:    Development/Libraries
Requires: libsodium

%description -n python3-%{srcname}
This library is used to gain direct access to the functions exposed by Daniel
J. Bernstein's nacl library via libsodium or tweetnacl. It has been constructed
to maintain extensive documentation on how to use nacl as well as being
completely portable. The file in libnacl/__init__.py can be pulled out and
placed directly in any project to give a single file binding to all of nacl.
%endif


%prep
%setup -q -n %{srcname}-%{version}

%if 0%{?with_python3}
rm -rf %{py3dir}
cp -a . %{py3dir}
%endif

%build
%{__python} setup.py build

%if 0%{?with_python3}
pushd %{py3dir}
%{__python3} setup.py build
popd
%endif

%install
rm -rf %{buildroot}
python setup.py install --skip-build --root %{buildroot}

%if 0%{?with_python3}
pushd %{py3dir}
%{__python3} setup.py install --skip-build --root %{buildroot}
popd
%endif

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{python2_sitelib}/*

%if 0%{?with_python3}
%files -n python3-%{srcname}
%defattr(-,root,root,-)
%{python3_sitelib}/*
%endif

%changelog
* Fri Jun 20 2014 Erik Johnson <erik@saltstack.com> - 1.1.0-1
- Updated to 1.1.0

* Fri Jun 20 2014 Erik Johnson <erik@saltstack.com> - 1.0.0-1
- Initial build
