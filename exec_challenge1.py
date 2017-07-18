#!/usr/bin/env python

import json
import os_client_config
#import paramiko

chall_IPs = {}
conn = os_client_config.make_sdk()
with open("chall_servers.json") as f:
    chall_server = json.load(f)
for server_name, server_data in enumerate(chall_server):
    chall_IPs[server_name] = server_data["id"]
while 1:
    with open("chall_ready.json") as f:
        chall_ready = json.load(f)
    with open("chall_teams.json") as f:
        chall_teams = json.load(f)
 
    new_team = False

    for chall_name in chall_ready:
        server = conn.compute.get_server(chall_server[chall_name]["id"])
        if server.status != "ACTIVE" and new_team:
            conn.compute.start_server(server)
            print("ssh ip_chall -c start_container &",team_id, " deu certo? ", chall_name)
        elif new_team:
            print("ssh ip_chall -c start_container &",team_id, " deu certo? ", chall_name)

        for team_id, team_data in enumerate(chall_teams):
            if chall_name in team_data["solved"] and team_solve:
                print("ssh ip_chall -c stop_container ",team_id, " deu certo? ", chall_name)
#        print(chall_name+": ",server.addresses["teste_net"][1]["addr"])
