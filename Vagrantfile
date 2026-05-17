Vagrant.configure("2") do |config|
  config.vm.synced_folder ".", "/vagrant"

  config.vm.define "ubuntu" do |u|
    u.vm.box = "bento/ubuntu-22.04"
    u.vm.hostname = "ubuntu"
    u.vm.provider "virtualbox" do |vb|
      vb.memory = 512
      vb.cpus = 1
    end
    u.vm.provision "shell", inline: <<-SHELL
      bash /vagrant/scripts/build_check.sh
      echo "=== check ==="
      python3 /vagrant/dist/patch-checker.pyz check || true
      echo "=== check --json ==="
      python3 /vagrant/dist/patch-checker.pyz check --json
    SHELL
  end

  config.vm.define "almalinux" do |a|
    a.vm.box = "almalinux/9"
    a.vm.hostname = "almalinux"
    a.vm.provider "virtualbox" do |vb|
      vb.memory = 512
      vb.cpus = 1
    end
    a.vm.provision "shell", inline: <<-SHELL
      dnf install -y -q python3
      bash /vagrant/scripts/build_check.sh
      echo "=== check ==="
      python3 /vagrant/dist/patch-checker.pyz check || true
      echo "=== check --json ==="
      python3 /vagrant/dist/patch-checker.pyz check --json
    SHELL
  end
end
