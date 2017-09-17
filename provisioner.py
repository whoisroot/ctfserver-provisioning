#!/usr/bin/env python3

import json
import os_client_config
import paramiko
import os
import time
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from subprocess import Popen
from pwgen import pwgen

logging.basicConfig(level=logging.INFO)


CTF_network = "ctf_net" # Name of the network on OpenStack used for the CTF
IP_type = 0 # 0 for internal network, 1 for IPv6, 2 for floating IP
NIZKCTF_PATH = "" # Path to the NIZKCTF repository
VPN_VM_IP = "" # The floating/external IP of the VM with the VPN server containers
min_solves = 1 # Minimum number of solves required for team to be provisioned
VM_user = "ubuntu" # User to authenticate and start containers in the challenge VMs
VM_ssh_port = 22 # SSH port to authenticate and start containers in the challenge VMs
max_concurrent_connections = 10 # maximum concurrent connections to SSH or OpenStack API


def main_loop(chall_server):
    size_ready = 0
    teams_playing = 0

    executor = ThreadPoolExecutor(max_workers=max_concurrent_connections)

    logging.info("Starting the main loop")
    while 1:
        solves_list = []
        new_teams_list = []
        new_team = False
        new_chall = False
        new_solves = False

        with open("chall_ready.json") as f:
            chall_ready = json.load(f)

        if len(chall_ready) > size_ready:
            new_chall = True
            diff_pos = len(chall_ready) - size_ready - 1
            size_ready = len(chall_ready)

        new_team, new_teams_list, new_solves, solves_list, teams = update_score(NIZKCTF_PATH, min_solves, chall_ready) # Checks for new teams and solves on scoreboard

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
                start_vpn(team_id, teams)
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


def start_vpn(team_id):
    try:
        password = pwgen(pw_length=20, no_ambiguous=True)
        user = "team-%d" % team_id
        message = "Run: ./setup-vpn '%s' '%s' '%s'" % (user, password, VPN_VM_IP)
        # Start the container for the specified team
        command = "./deploy_team %d %s %s" % (team_id, user, password)
        output = ssh_exec(VPN_VM_IP, command)
        if output[-1].split(':') == 'ok':
            return ("start_vpn", (team_id, message))
            #p = Popen([NIZKCTF_PATH+"/ctf", "add_news", "--msg", message, "--to", teams[team_id]["name"]])
            #p.wait()
        logging.error("Unexpected output from start_vpn(%d): %s",
                      team_id, '\n'.join(output))
    except:
        logging.exception("Got exception on start_vpn(%d)", team_id)
    return None


def start_container(host, team_id):
    try:
        command = "./start_container %d" % team_id
        status, container_name = ssh_exec(host, command).split(':')
        assert status in ('started', 'already_started')
        if status == 'already_started':
            logging.warn('Container %s was already started in host %s',
                         container_name, host)
        return ("start_container", (host, team_id))
    except:
        logging.exception("Got exception on start_container(%s, %d)",
                          host, team_id)
    return None


def stop_container(host, team_id):
    try:
        command = "./stop_container %d" % team_id
        status, container_name = ssh_exec(host, command).split(':')
        assert status in ('stopped', 'already_stopped')
        if status == 'already_stopped':
            logging.warn('Container %s was already stopped in host %s',
                         container_name, host)
        return ("stop_container", (host, team_id))
    except:
        logging.exception("Got exception on stop_container(%s, %d)",
                          host, team_id)
    return None


def list_containers(host):
    return ssh_exec(host, 'lxc list --format=csv --columns=n').split()


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
            client.connect(host, VM_ssh_port, VM_user,
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


def update_score(path, minSolves, chall_ready):
    with open(path+"/submissions/accepted-submissions.json") as f:
        accepted_submissions = json.load(f) # Polls the scoreboard
    if len(accepted_submissions) == 0:
        return False, [], False, [], []
    with open("chall_teams.json") as f:
        chall_teams = json.load(f) # Current teams being provisioned

    size = len(chall_teams)
    solve = False
    new_team = False
    new_teams_list = []
    solves_list = []

    for team in accepted_submissions["standings"]:
        team_id = -1
        for i in range(0, size):
            # Checks if team already being provisioned and their ID
            if team["team"] == chall_teams[i]["name"]:
                team_id = i
                break
        # New team, add them to the end of the file containing teams
        if team_id < 0 and len(team["taskStats"]) >= minSolves:
            chall_teams.append({"name": team["team"], "solved": []})
            new_team = True
            new_teams_list.append(size)
            size += 1
        else:
            for challenge in team['taskStats']:
                # Checks for newly solved challenges and add the to the team solves
                if challenge in chall_ready:
                    if challenge not in chall_teams[team_id]["solved"]:
                        chall_teams[team_id]["solved"].append(challenge)
                        solve = True
                        solves_list[challenge].append(team_id)
    with open("chall_teams.json", 'w') as f:
        json.dump(chall_teams, f) # Saves the final result
    return new_team, new_teams_list, new_solves, solves_list, chall_teams


def idle_vm_shutoff(server):
    # Can only shutdown active servers
    if server["power_state"] == "on":
        vm_ip = server["IP"]
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.connect(vm_ip, 22, VM_user) #IP, port, username
        stdin, stdout, stderr = client.exec_command("lxc list | grep RUNNING | wc -l") # Get number of running containers
        for line in stdout:
            containers = int(line.strip('\n'))
        # Shutdown VM if not in use
        if containers == 0:
            conn.compute.stop_server(server)
    else:
        pass


def vm_start(server):
    if server["power_state"] == "off":
        conn.compute.get_server(server["id"])
        while vm.status == "SHUTOFF":
            sleep(3)
            vm = conn.compute.get_server(server["id"])
        server["power_state"] = "on"
    else:
        pass


conn = os_client_config.make_sdk()
with open("chall_servers.json") as f:
    chall_server = json.load(f)
    for chall in chall_server:
        for i in range(0,len(chall_server[chall])):
            vm = conn.compute.get_server(chall_server[chall][i]["id"])
            chall_server[chall][i]["IP"] = vm.addresses[CTF_network][IP_type]["addr"]
            if vm.status == "SHUTOFF":
                chall_server[chall][i]["power_state"] = "off"
            elif vm.status == "ACTIVE":
                chall_server[chall][i]["power_state"] = "on"
            else:
                logging.critical('VM %s IN UNKNOWN STATE, PLEASE CHECK OPENSTACK', chall)
    json.dump(chall_server, f)


print("Challenge VMs IPs:\n")
print(chall_server,"\n\n")
main_loop(chall_server)