# Installation for Ansible on device - Ubuntu 18.04 (only OS tested)
# See more here: https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-ansible-on-ubuntu-18-04

# Get the latest version for Ubuntu - add personal package archive (PPA) to this machine
sudo apt-get update
sudo apt install software-properties-common

# use apt-add-repository with -y flag to assume yes on all quries
sudo apt-add-repository -y ppa:ansible/ansible

# refresh the system's package index to be aware of the packages found in this new added PPA
sudo apt-get update

# then, install the ansible package (also assume yes for all queries)
sudo apt-get install -y ansible

# check in the end the version of ansible
ansible --version

