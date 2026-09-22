# Vagrant setup for school (x86-64 host) — same provisioning as the local QEMU VM.
# Usage on a school machine:
#   vagrant up          # downloads box, boots, runs provision.sh
#   vagrant ssh         # or: ssh cjung-mo@localhost -p 2222 (password: 42)
#   vagrant halt / destroy
Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.hostname = "ft-traceroute"

  # ft_traceroute sources shared into the VM at /home/vagrant/ft_traceroute
  config.vm.synced_folder ".", "/home/vagrant/ft_traceroute"

  config.vm.provision "shell", path: "provision.sh"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
  end
  config.vm.provider "libvirt" do |lv|
    lv.memory = 2048
    lv.cpus = 2
  end
end
