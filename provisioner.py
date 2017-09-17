#!/usr/bin/env python3

import json
import os_client_config
import paramiko
import os
import time
import shlex
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from subprocess import Popen
from pwgen import pwgen

logging.basicConfig(level=logging.INFO)
openstack = os_client_config.make_sdk()


#
# Configuration
#
CTF_NETWORK = "ctf_net" # Name of the network on OpenStack used for the CTF
# Constraints for the addresses to which the provisioner connects
ADDR_CONSTRAINTS = {('version', 4),  # 4 for IPv4, 6 for IPv6
                    ('OS-EXT-IPS:type', 'fixed')}  # 'fixed' for internal network, 'floating' for floating IP
# Constraints for external addresses given to users (e.g. VPN address)
EXTADDR_CONSTRAINTS = {('version', 4),
                       ('OS-EXT-IPS:type', 'floating')}
NIZKCTF_PATH = "" # Path to the NIZKCTF repository
MIN_SOLVES = 1 # Minimum number of solves required for team to be provisioned
SSH_USER = "ubuntu" # User to authenticate and start containers in the challenge VMs
SSH_PORT = 22 # SSH port to authenticate and start containers in the challenge VMs
MAX_CONCURRENT_CONNS = 10 # maximum concurrent connections to SSH or OpenStack API
ITERATIONS_BETWEEN_SYNCS = 10 # number of main loop iterations between state syncs

OPENSTACK_SERVERS = "openstack_servers.json"
RELEASED_CHALLS = "released_challs.json"
VPN_ID = "_vpn"  # VPN server name in OPENSTACK_SERVERS json file


class VMState:
    def __init__(self, status, addr, extaddr=None):
        self.status = status
        self.addr = addr
        self.extaddr = extaddr
    def __repr__(self):
        return '<VMState(%r, %r, %r)>' % (self.status, self.addr, self.extaddr)


def main_loop(chall_server):
    executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CONNS)
    iteration = 0
    released_challs = []
    logging.info("Starting the main loop")

    while True:
        previously_released_challs = released_challs
        released_challs = read_released_challs()

        if iteration == 0 or released_challs != previously_released_challs:
            logging.info("Syncing state")
            openstack_servers, vm_state = sync_vms()
            vpn_addr, vpn_extaddr = get_vpn_addrs(openstack_servers, vm_state)
        iteration = (iteration + 1) % ITERATIONS_BETWEEN_SYNCS

        pending = []

        # If there are new solves, stop the containers in the solves list
        if new_solves:
            for challenge in solves_list:
                for team in solves_list[challenge]:
                    logging.info("Stopping chall %s containers for team %s", challenge, team)
                    for server in chall_server[challenge]:
                        pending.append(executor.submit(stop_container(server, team)))

        # If there are new teams, start a container in every challenge VM for each new team
        if new_team:
            logging.info("Provisioning containers for new teams %r", new_teams_list)
            for team_id in new_teams_list:
                start_vpn(vpn_addr, vpn_extaddr, team_id)
            for chall_name in chall_ready:
                for server in chall_server[chall_name]:
                    for team_id in new_teams_list:
                        pending.append(executor.submit(start_container(server, team_id)))
            teams_playing += len(new_teams_list)

        # If there are new challenges, start a container for every team playing in the new VM
        if new_chall:
            for i in range(size_ready-diff_pos, size_ready):
                chall_name = chall_ready[i]
                for server in chall_server[chall_name]:
                    for team_id in range(0, teams_playing - 1):
                        pending.append(executor.submit(start_container(server, team_id)))

        for func, args in wait_pending(pending):
            if func == "start_vpn":
                team_id, message = args
                p = Popen([NIZKCTF_PATH+"/ctf", "add_news",
                           "--msg", message,
                           "--to", teams[team_id]["name"]])
                p.wait()
            elif func == "start_container":
                host, team_id = args
                # TODO
            elif func == "stop_container":
                host, team_id = args
                # TODO

        for chall_name in chall_ready:
            for server in chall_server[chall_name]:
                idle_vm_shutoff(server) # Check all VMs to test if there are containers running, shut them down if not

        time.sleep(60)


def start_vpn(host, extaddr, team_id):
    try:
        password = pwgen(pw_length=20, no_ambiguous=True)
        message = "Run: ./setup-vpn %s %d %s" % (shlex.quote(extaddr),
                                                 team_id,
                                                 shlex.quote(password))
        # Start the container for the specified team
        command = "./deploy_team %d %s" % (team_id,
                                           shlex.quote(password))
        output = ssh_exec(host, command)
        status = output[-1].split(':')[0]
        if status == 'vpn_created':
            return ("start_vpn", (team_id, message))
        elif status == 'vpn_already_exists':
            logging.warn('VPN for team %d was already started' % team_id)
            return None
        logging.error("Unexpected output from start_vpn(%r, %r, %d): %s",
                      host, extaddr, team_id, '\n'.join(output))
    except:
        logging.exception("Got exception on start_vpn(%r, %r, %d)",
                          host, extaddr, team_id)
    return None


def start_container(host, team_id):
    try:
        command = "./start_container %d" % team_id
        status, container_name = ssh_exec(host, command).split(':')
        assert status in ('started', 'already_started')
        if status == 'already_started':
            logging.warn('Container %r was already started in host %r',
                         container_name, host)
        return ("start_container", (host, team_id))
    except:
        logging.exception("Got exception on start_container(%r, %d)",
                          host, team_id)
    return None


def stop_container(host, team_id):
    try:
        command = "./stop_container %d" % team_id
        status, container_name = ssh_exec(host, command).split(':')
        assert status in ('stopped', 'already_stopped')
        if status == 'already_stopped':
            logging.warn('Container %r was already stopped in host %r',
                         container_name, host)
        return ("stop_container", (host, team_id))
    except:
        logging.exception("Got exception on stop_container(%r, %d)",
                          host, team_id)
    return None


def list_containers(uuid, host):
    try:
        containers = ssh_exec(host,
                              "lxc list --format=csv --columns=n "
                              "'^team-'").split()
        return ("list_containers", (uuid, containers))
    except:
        logging.exception("Got exception on list_containers(%r, %r)",
                          uuid, host)
    return None


def wait_pending(pending, timeout=60):
    try:
        for future in as_completed(pending, timeout=60):
            result = future.result()
            if result is not None:
                yield result
    except TimeoutError:
        logging.exception("Timeout when waiting for threads to finish")


def ssh_exec(host, command, retries=5, timeout=2):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for i in range(retries):
        try:
            client.connect(host, SSH_PORT, SSH_USER,
                           timeout=timeout,
                           banner_timeout=timeout,
                           auth_timeout=timeout)
            break
        except:
            logging.exception('Got exception at ssh_exec')
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode('utf-8').strip()
    errout = stderr.read().decode('utf-8').strip()
    if errout != '':
        logging.error("Received errors when running '%s' on host %s: %s",
                      command, host, errout)
    client.close()
    return output


def idle_vm_shutoff(server):
    # Can only shutdown active servers
    if server["power_state"] == "on":
        vm_ip = server["IP"]
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.connect(vm_ip, 22, SSH_USER) #IP, port, username
        stdin, stdout, stderr = client.exec_command("lxc list | grep RUNNING | wc -l") # Get number of running containers
        for line in stdout:
            containers = int(line.strip('\n'))
        # Shutdown VM if not in use
        if containers == 0:
            openstack.compute.stop_server(server)
    else:
        pass


def vm_start(server):
    if server["power_state"] == "off":
        openstack.compute.get_server(server["id"])
        while vm.status == "SHUTOFF":
            sleep(3)
            vm = openstack.compute.get_server(server["id"])
        server["power_state"] = "on"
    else:
        pass


def read_released_challs():
    with open(RELEASED_CHALLS) as f:
        return json.load(f)


def sync_containers(openstack_servers, vm_state):
    executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CONNS)
    pending = []

    for chall, vm_uuids in openstack_servers.items():
        for vm_uuid in vm_uuids:
            state = vm_state[vm_uuid]
            if state.status == "on":
                container_state[vm_uuid] = []
            else:
                pending.append(executor.submit(list_containers,
                                               (vm_uuid, state.addr)))

    container_state = {}
    for func, args in wait_pending(pending):
        uuid, containers = args
        container_state[uuid] = containers

    return container_state


def sync_vms():
    with open(OPENSTACK_SERVERS) as f:
        openstack_servers = json.load(f)

    vm_state = {}

    for chall, vm_uuids in openstack_servers.items():
        for vm_uuid in vm_uuids:
            vm = openstack.compute.get_server(vm_uuid)

            if vm.status == "SHUTOFF":
                status = "off"
            elif vm.status == "ACTIVE":
                status = "on"
            else:
                logging.critical('VM %s IN UNKNOWN STATE, CHECK OPENSTACK',
                                 vm_uuid)
                status = "off"  # assume off

            def get_addr(constraints):
                try:
                    return next(addrinfo["addr"]
                                for addrinfo in vm.addresses[CTF_NETWORK]
                                if constraints.issubset(addrinfo.items()))
                except StopIteration:
                    return None

            addr = get_addr(ADDR_CONSTRAINTS)
            extaddr = get_addr(EXTADDR_CONSTRAINTS)
            vm_state[vm_uuid] = VMState(status, addr, extaddr)

    return openstack_servers, vm_state


def get_vpn_addrs(openstack_servers, vm_state):
    vpn_uuid, = openstack_servers[VPN_ID]
    state = vm_state[vpn_uuid]
    if state.status != "on":
        logging.critical("THE VPN VM IS OFF, TURN IT ON")
    return state.addr, state.extaddr


if __name__ == '__main__':
    main_loop(chall_server)
