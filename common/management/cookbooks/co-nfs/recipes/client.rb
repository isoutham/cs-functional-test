#
# Cookbook Name:: co-nfs
# Recipe:: clients
#
# Copyright 2011, Matthieu Serrepuy
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
has_nfs_scope_ip_address = true

unless node["nfs"]["shares"].empty?
   ## If your node should use an nfs mount point
   unless node["nfs"]["config"]["nfs_network"] == false
	## Check your network interfaces and verify you have an IP in the NFS network
	has_nfs_scope_ip_address = false
	node['network']['interfaces'].each do |i,u|
		u['addresses'].each do |a,r|
			if r['broadcast'] == "#{node["nfs"]["config"]["nfs_network"]}"
				has_nfs_scope_ip_address = true
			end
		end
	end
   end

   ## If your node has an IP in the good scope OR you don't want to check the IP scope
   if has_nfs_scope_ip_address == true
	Chef::Log.info("co-nfs: IP check disabled or NFS IP validated")
	node["nfs"]["shares"].each do |mount_point,m|
		directory "#{mount_point}" do
			owner "root"
			group "root"	
			mode "0755"
			action :create
			recursive true
			not_if "test -d #{mount_point}"
		end
			
		mount "#{mount_point}" do
			device 	"#{m['server']}:#{m['remote_folder']}"
			fstype 	"nfs"
			if m['nfs_options'].nil?
				options "rw,noatime,hard,timeo=10,retrans=2"
			else
				options "#{m['nfs_options']}"
			end
			action [:mount, :enable]
		end
	end
   else
	Chef::Log.error("co-nfs: No NIC in NFS Network")
   end
end
