#
# spec file for package python-libnacl
#
# Copyright (c) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

Name:           python-libnacl
Version:        1.4.3
Release:        0
License:        Apache-2.0
Summary:        Python bindings for libsodium based on ctypes
Url:            https://github.com/saltstack/libnacl
Group:          Development/Languages/Python
Source0:        https://pypi.python.org/packages/source/l/libnacl/libnacl-%{version}.tar.gz
BuildRoot:      %{_tmppath}/libnacl-%{version}-build

BuildRequires:  python-setuptools
BuildRequires:  python-devel
BuildRequires:  libsodium-devel
BuildRequires:  fdupes

BuildRoot:      %{_tmppath}/%{name}-%{version}-build
%if 0%{?suse_version} && 0%{?suse_version} <= 1110
%{!?python_sitelib: %global python_sitelib %(python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%else
BuildArch:      noarch
%endif

%description
This library is used to gain direct access to the functions exposed by Daniel J. Bernstein's nacl library via libsodium.
It has been constructed to maintain extensive documentation on how to use nacl as well as being completely portable. The file 
in libnacl/__init__.py can be pulled out and placed directly in any project to give a single file binding to all of nacl.

%prep
%setup -q -n libnacl-%{version}

%build
python setup.py build

%install
python setup.py install --prefix=%{_prefix} --root=%{buildroot} --optimize=1
%fdupes %{buildroot}%{_prefix}

%files
%defattr(-,root,root)
%{python_sitelib}/*

%changelog