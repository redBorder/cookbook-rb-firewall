Name: cookbook-rb-firewall
Version: %{__version}
Release: %{__release}%{?dist}
BuildArch: noarch
Summary: Firewall cookbook to install and configure it in redborder environments

License: AGPL 3.0
URL: https://github.com/redBorder/cookbook-rb-firewall
Source0: %{name}-%{version}.tar.gz

%description
%{summary}

%prep
%setup -qn %{name}-%{version}

%build

%install
mkdir -p %{buildroot}/var/chef/cookbooks/rb-firewall
cp -f -r  resources/* %{buildroot}/var/chef/cookbooks/rb-firewall
chmod -R 0644 %{buildroot}/var/chef/cookbooks/rb-firewall
install -D -m 0644 README.md %{buildroot}/var/chef/cookbooks/rb-firewall/README.md

%pre

%post
case "$1" in
  1)
    # This is an initial install.
    :
  ;;
  2)
    # This is an upgrade.
    su - -s /bin/bash -c 'source /etc/profile && rvm gemset use default && env knife cookbook upload rb-firewall'
  ;;
esac

%files
%defattr(0644,root,root)
/var/chef/cookbooks/rb-firewall
# %defattr(0644,root,root)
# /var/chef/cookbooks/rb-firewall/README.md

%doc

%changelog
* Mon Nov 25 2024 Luis J. Blanco <ljblanco@redborder.com>
- remove execution permission to the full path of the cookbook
* Tue Oct 08 2024 Nils Verschaeve <nverschaeve@redborder.com>
- first spec version
