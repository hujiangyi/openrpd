APT_INSTALLS="bridge-utils \
	build-essential \
        daemontools \
        gawk \
        gettext \
        git-core \
        libffi-dev \
        libncurses5-dev \
        libssl-dev \
        libvirt-bin \
        mercurial \
        protobuf-c-compiler \
        protobuf-compiler \
        psmisc \
        pylint \
        python-dev \
        python-paramiko \
        python-pip \
        python-protobuf \
        qemu-kvm \
        redis-server \
        sshpass \
        subversion \
        ubuntu-vm-builder \
        unzip"

apt-get update
apt-get upgrade -y

pip install ipaddress

for PKG in $APT_INSTALLS; do
	apt-get install -y $PKG
done


