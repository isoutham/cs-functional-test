#
# Cookbook Name:: nat-router
# Recipe:: default
#

package 'iptables'

directory "/etc/sysctl.d" do
  owner "root"
  group "root"
  mode 0644
end

template '/etc/sysctl.d/60-network-forwarding.conf' do
  source 'network-forwarding.conf.erb'
  mode 0644
  owner 'root'
  group 'root'
end

execute 'reload sysctl' do
  command 'sysctl -p /etc/sysctl.d/60-network-forwarding.conf'
  action :run
end

template '/etc/sysconfig/iptables' do
  source 'iptables.erb'
  mode 0644
  owner 'root'
  group 'root'
end

execute 'iptables-restore' do
  command '/sbin/iptables-restore < /etc/sysconfig/iptables'
  action :run
end
