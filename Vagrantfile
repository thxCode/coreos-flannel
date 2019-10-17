# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "bento/ubuntu-18.04"

  config.vm.synced_folder "..", "/go/src/github.com/coreos"

  config.vm.provider "virtualbox" do |vb|
    vb.cpus = 2
    vb.memory = 1024
  end

  config.vm.provision "shell", inline: <<-SHELL
    set -e -x -u
    apt-get update -y || (sleep 40 && apt-get update -y)
    apt-get install -y git gcc-multilib gcc-mingw-w64 zip
    wget -qO- https://dl.google.com/go/go1.11.5.linux-amd64.tar.gz | tar -C /usr/local -xz
    echo 'export GOPATH=/go' >> /home/vagrant/.bashrc
    echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' >> /home/vagrant/.bashrc
  SHELL
end