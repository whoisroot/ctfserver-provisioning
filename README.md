# Setting up NIZKCTF's provisioner


## Installing the required dependencies

The provisioner needs a few python3 dependencies to run:
* pwgen
* paramiko
* os_client_config

They are listed in `pip-requirements.txt`, just run `sudo -H python3 -m pip3 install -r pip-requirements.txt` to install the needed versions.

## Setting up the environment

Use the [Continuous Integration bot's](https://github.com/pwn2winctf/nizkctf-tutorial/blob/master/GitHub.md) SSH credentials to be able to access the other VMs in the server. To be able to use Openstack's environment you also need to authenticate using `source openstack.sh`, otherwise the `openstack` command options won't show.

1. Get the IDs of the challenges' VMs that will need provisioning through `openstack server list`.

2. Paste them in `openstack_servers.json` using the following template:
	- `{
		"<challenge1_name_in_NIZKCTF_here>": [<instance1_id_here>]
		"<challenge2_name_in_NIZKCTF_here>": [<instance2_id_here>]
   	   }`
	- Add the VPN instance to this file so that the provisioner can access it, just don't add it to `released_challs.json`, because it might get closed down by the provisioner's routines.

3. Get the same instance name used in `openstack_servers.json` and paste it in `released_challs.json` using the following template:
	- `["<instance_name>", "<instance2_name>"]`

With these steps you are ready to run the provisioner, as it will be able to provision e.g. our 2 challenge instances that were just added to the JSON files.

## Running the Provisioner

After completing the previous steps, just run the provisioner with `./provisioner.py` and it will do it's thing, if any error comes up, the output logs will show up.

To add new challenges after the provisioner is already running, just edit the JSON files the same way as the previous steps and they will be added to the routines in the next loop.
