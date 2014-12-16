co-nfs Cookbook
===============

Installs and configures NFS client, or server components.
Based on original [Chef community cookbooks](https://github.com/atomic-penguin/cookbook-nfs "Eric G. Wolfe Github") .


Requirements
------------

Should work on any Red Hat-family or Debian-family Linux distribution.


Basic Usage
-----------

Define shares on the node as follow for NFSserver:

```json
{
  "nfs":{
    "exports":[
      "/data/nfs/primary *(rw,async,no_root_squash)",
      "/data/nfs/secondary 172.16.21.0/24(rw,async,no_root_squash)",
      "/data/iso *(rw,async,no_root_squash)"
      ]
    }
}
```


Attributes
----------

* nfs['packages']

  - Makes a best effort to choose NFS client packages dependent on platform
  - NFS server package needs to be hardcoded for Debian/Ubuntu in the server
    recipe, or overridden in a role.

* nfs['service']
  - portmap - the portmap or rpcbind service depending on platform
  - lock - the statd or nfslock service depending on platform
  - server - the server component, nfs or nfs-kernel-server depending on platform

* nfs['config']
  - client\_templates - templates to iterate through on client systems, chosen by platform
  - server\_template - server specific template, chosen by platform

* nfs['port']

  - ['statd'] = Listen port for statd, default 32765
  - ['statd\_out'] = Outgoing port for statd, default 32766
  - ['mountd'] = Listen port for mountd, default 32767
  - ['lockd'] = Listen port for lockd, default 32768

* nfs['exports']

  - This may be replaced in the future by an LWRP to load export definitions from
    a data bag.  For now, its a simple array of strings to populate in an export file.
    Note: The "nfs::exports" recipe is separate from the "nfs::server" recipe.

* nfs['config']['nfs_network'] 

  - If the value is a broadcast IP (like 10.60.250.255), it checks that an NIC is configured inside that network before mounting any NFS mount point
  - If value is false, it does not check an y IP, it will mount your NFS share
  - default is false


Usage
-----

#### CLIENT :
To install the NFS components for a client system, simply add co-nfs::client to the run_list.

<tt>run_list => [ "co_nfs::client" ]</tt>

To define a share, you need to apply the following attributes :

```json
	"nfs": {
		"shares": {
			"/local/mount/point": {
				"server": 		"nfs_server_ip_or_hostname",
				"remote_folder": 	"export_name",
				"nfs_options':		"nfs_mount_options"
			}
		}
	}
```

default nfs_options if not specified :
	<tt>rw,noatime,hard,timeo=10,retrans=2"</tt>

You can define an attribute :
	<tt>node["nfs"]["config"]["nfs_network"]</tt>

If it contains a network address, before creating the mount point, it will first check if an ip address inside that IP scope is available or not.
If not available, it will skip the mount point configuration.


#### SERVER :
Then in an <tt>nfs\_server.rb</tt> role that is applied to NFS servers:

```ruby
    name "nfs_server"
    description "Role applied to the system that should be an NFS server."
    override_attributes(
      "nfs" => {
        "packages" => [ "portmap", "nfs-common", "nfs-kernel-server" ],
        "ports" => {
          "statd" => 32765,
          "statd_out" => 32766,
          "mountd" => 32767,
          "lockd" => 32768
        },
        "exports" => [
          "/exports 10.0.0.0/8(ro,sync,no_root_squash)"
        ]
      }
    )
    run_list => [ "nfs::server", "nfs::exports" ]
```

LICENSE AND AUTHOR
==================

- Authors:: Eric G. Wolfe (<wolfe21@marshall.edu>)
- Authors:: Pierre-Luc Dion (<pdion@cloudops.com>)
- Authors:: Matthieu Serrepuy (mserrepuy@cloudops.com)

```text
Copyright:: Copyright (c) 2013 CloudOps.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
