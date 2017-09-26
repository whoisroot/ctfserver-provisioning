# Setting up NIZKCTF's provisioner


## Installing the required dependencies

The provisioner needs a few python3 dependencies to run:
* pwgen
* paramiko
* os_client_config

They are listed in `pip-requirements.txt`, just run `sudo -H python3 -m pip3 install -r pip-requirements.txt` to install the needed versions.

## Setting up the environment

Use the [Continuous Integration bot's](https://github.com/pwn2winctf/nizkctf-tutorial/blob/master/GitHub.md) SSH credentials to be able to access the other VMs in the server. To be able to use Openstack's environment you also need to authenticate using the `openrc.sh` file (which can be obtained in the top right corner of the OpenStack web interface after logging in), otherwise the `openstack` command options won't work.

1. Create the Virtual Machines for the VPN and the challenges and set them up using our [ansible playbooks](https://github.com/pwn2winctf/infra-playbooks/).
The setup order is:
* `ansible-playbook vpn_base_container.yml`
* `ansible-playbook vpn_host.yml`
* `ansible-playbook challenges.yml`

After that run `./disable-port-security server_name_or_uuid` to enable bridging the network to the challenge containers.

2. Copy the challenge container image to the designated challenge Virtual Machine and import it with `lxd image import your_challenge.tar.gz --alias chall_name` or create a brand new container and configure it to your liking and publish it later with `lxc publish container-name --alias chall_name --force`. More tutorials on LXD can be found at [the original documentation](https://help.ubuntu.com/lts/serverguide/lxd.html). The only requirement of the provisioner is that the container must have an static IP in the same range as the internal network provided for the VPN. In the default configuration of the playbooks, its `10.133.64.1/20` and, for ul7r4_1337 purposes, we recommend container IPs to be in the `10.133.70.0/24` range `;)` .
This can be done adding the following lines to `/etc/network/interfaces`:

        auto eth0
        iface eth0 inet static
            address 10.133.70.xxx/20

Edit the `start_container` script to use the alias you set for your container image.

3. Get the IDs of the challenges' VMs that will need provisioning through `openstack server list`.

4. Paste them in `openstack_servers.json` using the following template:

        {
            "_vpn": ["<VPN_VM_uuid_here>"],
            "<challenge1_name_in_NIZKCTF_here>": ["<instance1_uuid_here>"],
            "<challenge2_name_in_NIZKCTF_here>": ["<instance2_uuid_here>"],
            "<multicontainer-chall_name_here>": ["<instance3-1_uuid_here>", "<instance3-2_uuid_here>"]
        }

	- Add the VPN instance to this file so that the provisioner can access it, just don't add it to `released_challs.json`, because it might get closed down by the provisioner's routines.

5. Get the same instance name used in `openstack_servers.json` and paste it in `released_challs.json` using the following template:
	- `["<chall1_name>", "<chall2_name>"]`

6. Clone the NIZKCTF repo and the submissions repo inside it.

7. Edit the configuration variables at the start of the `provisioner.py` script, this should be self-explanatory if you read the comments on the code.

With these steps you are ready to run the provisioner, as it will be able to provision e.g. our 2 challenge instances that were just added to the JSON files.

## Running the Provisioner

After completing the previous steps, just run the provisioner with `./provisioner.py` and it will do it's thing, if any error comes up, the output logs will show up.

To add new challenges after the provisioner is already running, just edit the JSON files the same way as the previous steps and they will be added to the routines in the next loops.
