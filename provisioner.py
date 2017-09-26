#!/usr/bin/env python3

import os
import re
import time
import json
import shlex
import logging
import requests
import sqlite3
import os_client_config
import paramiko
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from subprocess import Popen
from collections import namedtuple
from pwgen import pwgen

logging.basicConfig(level=logging.INFO)


# Configuration
#################################################################
#
CTF_NETWORK = "ctf_net" # Name of the network on OpenStack used for the CTF
# Constraints for the addresses to which the provisioner connects
ADDR_CONSTRAINTS = {('version', 4),  # 4 for IPv4, 6 for IPv6
                    ('OS-EXT-IPS:type', 'fixed')}  # 'fixed' for internal network, 'floating' for floating IP
# Constraints for external addresses given to users (e.g. VPN address)
EXTADDR_CONSTRAINTS = {('version', 4),
                       ('OS-EXT-IPS:type', 'floating')}
NIZKCTF_PATH = "/home/ubuntu/SCMPv8" # Path to the NIZKCTF repository
MIN_SOLVES = 1 # Minimum number of solves required for team to be provisioned
SSH_USER = "ubuntu" # User to authenticate and start containers in the challenge VMs
SSH_PORT = 22 # SSH port to authenticate and start containers in the challenge VMs
MAX_CONCURRENT_CONNS = 10 # maximum concurrent connections to SSH or OpenStack API
MAX_PROVISIONED_ID = 4095 # maximum id for provisioned teams
ITERATIONS_BETWEEN_SYNCS = 10 # number of main loop iterations between state syncs
MAIN_LOOP_ITERATION_SLEEP = 60 # seconds to sleep between iterations
# URL from which we will get the accepted-submissions.json file
ACCEPTED_SUBMISSIONS_URL = "https://raw.githubusercontent.com/"\
    "SCMP-ctf/SCMPv8submissions/master/"\ # Submissions repository for the CTF
    "accepted-submissions.json"

OPENSTACK_SERVERS = "openstack_servers.json"
RELEASED_CHALLS = "released_challs.json"
TEAM_ID_DB = "team_id.db"
VPN_ID = "_vpn"  # VPN server name in OPENSTACK_SERVERS json file

CONTAINER_PREFIX = "team-"
#
#################################################################
#

VMState = namedtuple('VMState', ['status', 'addr', 'extaddr'])


def main_loop():
    iteration = 0
    released_challs = set([])
    vm_state = {}
    container_state = {}
    logging.info("Starting the main loop")

    while True:
        try:
            previously_released_challs = released_challs
            released_challs = read_released_challs()

            if iteration == 0 or released_challs != previously_released_challs:
                logging.info("Syncing state")

                previous_vm_state = vm_state
                previous_container_state = container_state

                openstack_servers, vm_state = sync_vms()
                container_state = sync_containers(openstack_servers, vm_state)

                if vm_state != previous_vm_state:
                    logging.warn('VM state changed from %r to %r',
                                 previous_vm_state, vm_state)
                if container_state != previous_container_state:
                    logging.warn('Container state changed from %r to %r',
                                 previous_container_state, container_state)

            iteration = (iteration + 1) % ITERATIONS_BETWEEN_SYNCS

            target_state = compute_target_state(openstack_servers,
                                                released_challs)

            start_vms(vm_state, container_state, target_state)

            handle_container_transition(openstack_servers, vm_state,
                                        container_state, target_state)
            if container_state != target_state:
                logging.error('Current state: %r. Failed to achieve state %r.',
                              container_state, target_state)

            stop_idle_vms(vm_state, container_state)
        except:
            logging.exception("Exception on main_loop")

        time.sleep(MAIN_LOOP_ITERATION_SLEEP)


def handle_container_transition(openstack_servers, vm_state,
                                container_state, target_state):
    executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CONNS)
    pending = []

    vpn_addr, vpn_extaddr = get_vpn_addrs(openstack_servers, vm_state)
    vpn_vm_uuids = set(openstack_servers[VPN_ID])

    logging.debug('Current state: %r. Target state: %r',
                  container_state, target_state)

    # Handle starting VPN if needed
    for vm_uuid in vpn_vm_uuids:
        for container in target_state[vm_uuid]:
            if container not in container_state[vm_uuid]:
                team_id = get_team_id_from_container_name(container)
                pending.append(executor.submit(start_vpn,
                                               vm_uuid,
                                               vpn_addr,
                                               vpn_extaddr,
                                               team_id))

    # Start challenge containers if needed
    for vm_uuid, containers in target_state.items():
        if vm_uuid in vpn_vm_uuids:
            continue
        for container in containers:
            if container not in container_state[vm_uuid]:
                team_id = get_team_id_from_container_name(container)
                pending.append(executor.submit(start_container,
                                               vm_uuid,
                                               vm_state[vm_uuid].addr,
                                               team_id))

    # Stop challenge containers if not needed anymore
    for vm_uuid, containers in container_state.items():
        if vm_uuid in vpn_vm_uuids:
            continue
        for container in containers:
            if container not in target_state[vm_uuid]:
                team_id = get_team_id_from_container_name(container)
                pending.append(executor.submit(stop_container,
                                               vm_uuid,
                                               vm_state[vm_uuid].addr,
                                               team_id))

    for func, args in wait_pending(pending):
        if func == "start_vpn":
            vm_uuid, team_id, message = args
            team_name = get_team_name(team_id)
            logging.info("Sending VPN credentials to team %r" % team_name)
            p = Popen([os.path.join(NIZKCTF_PATH, "ctf"), "add_news",
                       "--msg", message,
                       "--to", team_name])
            p.wait()
            container = get_container_from_team_id(team_id)
            container_state[vm_uuid].add(container)
        elif func == "start_container":
            vm_uuid, host, team_id = args
            container = get_container_from_team_id(team_id)
            container_state[vm_uuid].add(container)
        elif func == "stop_container":
            vm_uuid, host, team_id = args
            container = get_container_from_team_id(team_id)
            container_state[vm_uuid].remove(container)


def start_vms(vm_state, container_state, target_state):
    executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CONNS)
    pending = []

    for vm_uuid, containers in target_state.items():
        if len(containers) > 0 and len(container_state[vm_uuid]) == 0:
            if vm_state[vm_uuid].status == "off":
                pending.append(executor.submit(start_vm, vm_uuid))

    for func, args in wait_pending(pending):
        uuid, = args
        vm_state[uuid] = vm_state[uuid]._replace(status="on")


def stop_idle_vms(vm_state, container_state):
    executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CONNS)
    pending = []

    for vm_uuid, containers in container_state.items():
        if len(containers) == 0:
            if vm_state[vm_uuid].status == "on":
                pending.append(executor.submit(stop_vm, vm_uuid))

    for func, args in wait_pending(pending):
        uuid, = args
        vm_state[uuid] = vm_state[uuid]._replace(status="off")

    return container_state


def stop_vm(vm_uuid):
    try:
        logging.info("Stopping VM %s", vm_uuid)
        openstack = os_client_config.make_sdk()
        openstack.compute.stop_server(vm_uuid)
        return ("stop_vm", (vm_uuid, ))
    except:
        logging.exception("Got exception on stop_vm(%r)",
                          vm_uuid)
    return None


def start_vm(vm_uuid):
    try:
        logging.info("Starting VM %s", vm_uuid)
        openstack = os_client_config.make_sdk()
        while True:
            vm = openstack.compute.get_server(vm_uuid)
            if vm.status == "ACTIVE":
                break
            if vm.task_state != "powering-on":
                openstack.compute.start_server(vm_uuid)
            time.sleep(2)
        return ("start_vm", (vm_uuid, ))
    except:
        logging.exception("Got exception on start_vm(%r)",
                          vm_uuid)
    return None


def start_vpn(vm_uuid, host, extaddr, team_id):
    try:
        logging.info("Starting VPN for team %d", team_id)
        password = pwgen(pw_length=20, no_ambiguous=True)
        message = "Run: ./setup-vpn %s %d %s" % (shlex.quote(extaddr),
                                                 team_id,
                                                 shlex.quote(password))
        # Start the container for the specified team
        command = "./deploy_team %d %s" % (team_id,
                                           shlex.quote(password))
        output = ssh_exec(host, command).split()
        status = output[-1].split(':')[0]
        if status == 'vpn_created':
            return ("start_vpn", (vm_uuid, team_id, message))
        elif status == 'vpn_already_exists':
            logging.warn('VPN for team %d was already started' % team_id)
            return None
        logging.error("Unexpected output from start_vpn(%r, %r, %r, %d): %s",
                      vm_uuid, host, extaddr, team_id, '\n'.join(output))
    except:
        logging.exception("Got exception on start_vpn(%r, %r, %r, %d)",
                          vm_uuid, host, extaddr, team_id)
    return None


def start_container(vm_uuid, host, team_id):
    try:
        logging.info("Starting container in host %r for team %d",
                     host, team_id)
        command = "./start_container %d" % team_id
        status, container_name = ssh_exec(host, command).split(':')
        assert status in ('started', 'already_started')
        if status == 'already_started':
            logging.warn('Container %r was already started in host %r',
                         container_name, host)
        return ("start_container", (vm_uuid, host, team_id))
    except:
        logging.exception("Got exception on start_container(%r, %r, %d)",
                          vm_uuid, host, team_id)
    return None


def stop_container(vm_uuid, host, team_id):
    try:
        logging.info("Stopping container in host %r for team %d",
                     host, team_id)
        command = "./stop_container %d" % team_id
        status, container_name = ssh_exec(host, command).split(':')
        assert status in ('stopped', 'already_stopped')
        if status == 'already_stopped':
            logging.warn('Container %r was already stopped in host %r',
                         container_name, host)
        return ("stop_container", (vm_uuid, host, team_id))
    except:
        logging.exception("Got exception on stop_container(%r, %r, %d)",
                          vm_uuid, host, team_id)
    return None


def list_containers(vm_uuid, host):
    try:
        containers = ssh_exec(host,
                              "lxc list --format=csv --columns=n "
                              "'^%s'" % CONTAINER_PREFIX).split()
        return ("list_containers", (vm_uuid, set(containers)))
    except:
        logging.exception("Got exception on list_containers(%r, %r)",
                          vm_uuid, host)
    return None


def ssh_exec(host, command, retries=10, timeout=4, sleep_interval=4):
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
            time.sleep(sleep_interval)
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode('utf-8').strip()
    errout = stderr.read().decode('utf-8').strip()
    if errout != '':
        logging.error("Received errors when running '%s' on host %s: %s",
                      command, host, errout)
    client.close()
    return output


def compute_target_state(openstack_servers, released_challs):
    containers = {}
    for chall, vm_uuids in openstack_servers.items():
        for vm_uuid in vm_uuids:
            containers[vm_uuid] = set()

    submissions = get_accepted_submissions()
    for team in submissions.get('standings', []):
        team_name = team['team']
        solved_challs = set(team['taskStats'].keys())
        if len(solved_challs) >= MIN_SOLVES:
            container_name = get_container_from_team_name(team_name)
            active_challs = released_challs - solved_challs
            active_challs.add(VPN_ID)  # the VPN containers are always on
            for chall in active_challs:
                for vm_uuid in openstack_servers[chall]:
                    containers[vm_uuid].add(container_name)

    return containers


def get_accepted_submissions():
    r = requests.get(ACCEPTED_SUBMISSIONS_URL, {'_': os.urandom(16)})
    r.raise_for_status()
    return r.json()


def get_container_from_team_name(team_name):
    return get_container_from_team_id(get_team_id(team_name))


def get_container_from_team_id(team_id):
    return "%s%d" % (CONTAINER_PREFIX, team_id)


def get_team_id_from_container_name(container_name):
    return int(re.match('^%s(\d+)$' % CONTAINER_PREFIX, container_name)
               .group(1))


def _create_db_get_cursor(conn):
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS "
                  "map (id INTEGER PRIMARY KEY CHECK(id <= %d), "
                  "     name UNIQUE);" %
                  (MAX_PROVISIONED_ID + 1,))
    return c


def get_team_id(team_name):
    with sqlite3.connect(TEAM_ID_DB) as conn:
        c = _create_db_get_cursor(conn)
        try:
            # INSERT OR IGNORE always increments the id :/
            c.execute("INSERT INTO map (name) VALUES (?1)",
                      (team_name,))
        except sqlite3.IntegrityError:
            pass # ID already allocated for team
        conn.commit()
        c.execute("SELECT id FROM map WHERE name=?1",
                  (team_name, ))
        team_id, = c.fetchone()
    return team_id - 1  # sqlite starts counting at 1


def get_team_name(team_id):
    with sqlite3.connect(TEAM_ID_DB) as conn:
        c = _create_db_get_cursor(conn)
        c.execute("SELECT name FROM map WHERE id=?1",
                  (team_id + 1, )) # sqlite starts counting at 1
        team_name, = c.fetchone()
    return team_name


def sync_containers(openstack_servers, vm_state):
    executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CONNS)
    container_state = {}
    pending = []

    for chall, vm_uuids in openstack_servers.items():
        for vm_uuid in vm_uuids:
            state = vm_state[vm_uuid]
            if state.status == "on":
                pending.append(executor.submit(list_containers,
                                               vm_uuid,
                                               state.addr))
            else:
                container_state[vm_uuid] = set()

    for func, args in wait_pending(pending, reraise=True):
        uuid, containers = args
        container_state[uuid] = containers

    return container_state


def sync_vms():
    openstack = os_client_config.make_sdk()

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
    return state.addr, state.extaddr


def read_released_challs():
    with open(RELEASED_CHALLS) as f:
        return set(json.load(f))


def wait_pending(pending, timeout=90, reraise=False):
    try:
        for future in as_completed(pending, timeout=60):
            result = future.result()
            if result is not None:
                yield result
    except TimeoutError:
        if reraise:
            raise
        logging.exception("Timeout when waiting for threads to finish")


if __name__ == '__main__':
    main_loop()
