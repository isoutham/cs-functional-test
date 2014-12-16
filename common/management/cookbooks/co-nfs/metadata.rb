maintainer       "Eric G. Wolfe"
maintainer_email "wolfe21@marshall.edu"
license          "Apache 2.0"
description      "Installs/Configures nfs"
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version          "0.2.0"

%w{ ubuntu debian redhat centos scientific amazon }.each do |os|
  supports os
end

recipe "co-nfs", "Installs nfs packages and libs"
recipe "co-nfs::client", "Install and configure NFS client"
recipe "co-nfs::server", "Install and configure NFS server daemon"
recipe "co-nfs::exports", "Configure shares on NFS server"
recipe "co-nfs::server_ha", ""