# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = '2'

Vagrant.require_version '>= 1.5.0'

unless Vagrant.has_plugin?('vagrant-librarian-chef')
  raise 'vagrant-librarian-chef is not installed!'
end

unless Vagrant.has_plugin?('vagrant-omnibus')
  raise 'vagrant-omnibus is not installed!'
end

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.vm.define 'xenserver' do |xenserver|
    xenserver.vm.box = 'duffy/xenserver'

    # Public Network (IP address is ignored.)
    xenserver.vm.network :private_network, :auto_config => false, :ip => '192.168.57.10'

    # Guest Network (IP address is ignored.)
    xenserver.vm.network :private_network, :auto_config => false, :ip => '192.168.58.10'

    # Configure Interfaces

    ## Configure Management Interface
    xenserver.vm.provision 'shell' do |s|
      s.path = 'common/xenserver/configure-network.sh'
      s.args = %w(eth1 192.168.56.10 255.255.255.0 MGMT)
    end

    ## Configure Public Interface
    xenserver.vm.provision 'shell' do |s|
      s.path = 'common/xenserver/configure-network.sh'
      s.args = %w(eth2 192.168.57.10 255.255.255.0 PUBLIC)
    end

    ## Configure Guest Interface
    xenserver.vm.provision 'shell' do |s|
      s.path = 'common/xenserver/configure-network.sh'
      s.args = %w(eth3 192.168.58.10 255.255.255.0 GUEST)
    end

    ## Tweak kernel
    xenserver.vm.provision "shell", inline: "sed -i -e 's/net.bridge.bridge-nf-call-iptables = 1/net.bridge.bridge-nf-call-iptables = 0/g' -e 's/net.bridge.bridge-nf-call-arptables = 1/net.bridge.bridge-nf-call-arptables = 0/g' /etc/sysctl.conf && /sbin/sysctl -p /etc/sysctl.conf"

    ## Map host only networks and the adapters
    xenserver.vm.provider 'virtualbox' do |v|
      v.customize ['modifyvm', :id, '--hostonlyadapter2', 'vboxnet0']
      v.customize ['modifyvm', :id, '--hostonlyadapter3', 'vboxnet1']
      v.customize ['modifyvm', :id, '--hostonlyadapter4', 'vboxnet2']
      v.customize ['modifyvm', :id, '--nicpromisc2', 'allow-all']
      v.customize ['modifyvm', :id, '--nicpromisc3', 'allow-all']
      v.customize ['modifyvm', :id, '--nicpromisc4', 'allow-all']
      v.customize ["modifyvm", :id, '--nictype2', 'Am79C973']
      v.customize ["modifyvm", :id, '--nictype3', 'Am79C973']
      v.customize ["modifyvm", :id, '--nictype4', 'Am79C973']
    end
   xenserver.vm.network 'forwarded_port', guest: 80, host: 4443
  end

  config.vm.define 'management' do |management|
    management.vm.box = 'chef/centos-6.5'

    # Configure management interface
    management.vm.network :private_network, :auto_config => true, :ip => '192.168.56.5'

    # Configure public interface
    management.vm.network :private_network, :auto_config => true, :ip => '192.168.57.5'

    # Port forward MySQL
    management.vm.network 'forwarded_port', guest: 3306, host: 3306

    # Port forward NFS
    management.vm.network 'forwarded_port', guest: 2049, host: 2049
    management.vm.network 'forwarded_port', guest: 32765, host: 32765
    management.vm.network 'forwarded_port', guest: 32766, host: 32766
    management.vm.network 'forwarded_port', guest: 32767, host: 32767

    management.vm.provider 'virtualbox' do |v|
      v.customize ['modifyvm', :id, '--memory', 2048]
      v.customize ['modifyvm', :id, '--hostonlyadapter2', 'vboxnet0']
      v.customize ['modifyvm', :id, '--hostonlyadapter3', 'vboxnet1']
      v.customize ["modifyvm", :id, '--nictype2', 'Am79C973']
      v.customize ["modifyvm", :id, '--nictype3', 'Am79C973']
    end

    management.omnibus.chef_version = "11.16.0"

    management.librarian_chef.cheffile_dir = 'common/management'

    management.vm.provision 'chef_solo' do |chef|
      chef.cookbooks_path = ['common/management/cookbooks']

      chef.run_list = [
          'recipe[cloudstack::default]'
      ]

      chef.json = {
          'iptables' => {
              'lans' => %w(eth1 eth2)
          }
      }
    end
	#config.vm.synced_folder ".", "/vagrant", type: "nfs"
  end
end
