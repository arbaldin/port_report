#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# v2.1 stable

import csv
import logging
import re

from alive_progress import alive_bar
from datetime import datetime
from getpass import getpass
from netmiko import Netmiko, NetmikoAuthenticationException


def load_devices(devices_db):
    devices_dict = {}
    with open(devices_db, "r") as csvdata:
        reader = csv.DictReader(filter(lambda row: row[0] != "#", csvdata))
        for row in reader:
            devices_dict[row["hostname"]] = {
                "conn_info": {
                    "device_type": row["device_type"],
                    "host": row["host"],
                    "username": user,
                    "password": passwd,
                    "global_delay_factor": int(row["global_delay_factor"]),
                },
                "vendor": row["vendor"],
                "site": row["site"],
                "service": row["service"],
            }
    return devices_dict


def conn_device(hostname, **device):
    try:
        net_connect = Netmiko(**device)
    except Exception as err:
        logger.error(f"{hostname}: {err}")
    return net_connect


def collect_dell_os9(conn, hostname):
    info_collected = []
    item_collected = {}
    index = 0
    cmd_output = conn.send_command("show interfaces status").splitlines()
    regex = re.compile(
        r"^([a-zA-Z]+\s\d\/\d{1,2})\s+(|\S+)\s+(Up|Down)\s+([a-zA-Z0-9]+(\s\S+|))\s+(\S+)\s+(\d+|--)$"
    )
    for item in cmd_output:
        if re.match(regex, item):
            item_collected["hostname"] = hostname.upper()
            item_collected["intf"] = re.match(regex, item).group(1).strip()
            item_collected["status"] = re.match(regex, item).group(3).strip()
            item_collected["type"] = "---"
            item_collected["speed"] = re.match(regex, item).group(4).strip()
            item_collected["duplex"] = re.match(regex, item).group(6).strip()
            info_collected.append(item_collected)
            item_collected = {}
    cmd_output = conn.send_command("show interfaces description").splitlines()
    regex = re.compile(
        r"^([a-ln-zA-LM-Z]+\s\d\/\d{1,2})\s+(YES|NO)\s+(up|down|admin down)\s+(up|down|not present)($|\s+\S*$)"
    )
    for item in cmd_output:
        if re.match(regex, item):
            info_collected[index]["description"] = (
                re.match(regex, item).group(5).strip()
            )
            index += 1
    return info_collected


def collect_extreme_nos(conn, hostname):
    info_collected = []
    item_collected = {}
    index = 0
    cmd_output = conn.send_command("show interface status").splitlines()
    regex = re.compile(
        r"^([a-zA-Z]+\s\d\/\d\/\d{,2})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)($|.+$)"
    )
    for item in cmd_output:
        if re.match(regex, item):
            item_collected["hostname"] = hostname.upper()
            item_collected["type"] = re.match(regex, item).group(5).strip()
            item_collected["status"] = re.match(regex, item).group(2).strip()
            item_collected["speed"] = re.match(regex, item).group(4).strip()
            item_collected["duplex"] = "---"
            info_collected.append(item_collected)
            item_collected = {}
    cmd_output = conn.send_command("show interface description").splitlines()
    regex = re.compile(r"^([a-zA-Z]+\s\d\/\d\/\d{,2})\s+(\S+)\s+(\S+)($|.+$)")
    for item in cmd_output:
        if re.match(regex, item):
            info_collected[index]["intf"] = re.match(regex, item).group(1).strip()
            info_collected[index]["description"] = (
                re.match(regex, item).group(4).strip()
            )
            index += 1
    return info_collected


def collect_extreme_netiron(conn, hostname):
    info_collected = []
    item_collected = {}
    cmd_output = conn.send_command("show interfaces brief wide").splitlines()
    regex = re.compile(
        r"^([0-9\/]+)\s+(Up|Disabled|Down)\s+([a-zA-Z\/]+)\s+([a-zA-Z0-9\/]+)\s+(Yes|No|N\/A)\s+(\w+\.\w+\.\w+|N\/A)($|\s+\S.*$)"
    )
    for item in cmd_output:
        if re.match(regex, item):
            item_collected["hostname"] = hostname.upper()
            item_collected["intf"] = re.match(regex, item).group(1).strip()
            item_collected["status"] = re.match(regex, item).group(2).strip()
            item_collected["speed"] = re.match(regex, item).group(4).strip()
            item_collected["duplex"] = "---"
            item_collected["type"] = "---"
            item_collected["description"] = re.match(regex, item).group(7).strip()
            info_collected.append(item_collected)
            item_collected = {}
    return info_collected


def collect_cisco_ios(conn, hostname):
    info_collected = []
    item_collected = {}
    index = 0
    cmd_output = conn.send_command("show interfaces status").splitlines()
    regex = re.compile(
        r"^([a-zA-Z]+(\d\/){1,2}\d{,2})\s+(|\S.+)(disabled|monitoring|connected|notconn.+?|sfpAbsent)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S.+?)$"
    )
    for item in cmd_output:
        if re.match(regex, item):
            item_collected["hostname"] = hostname.upper()
            item_collected["intf"] = re.match(regex, item).group(1).strip()
            item_collected["status"] = re.match(regex, item).group(4).strip()
            item_collected["speed"] = re.match(regex, item).group(7).strip()
            item_collected["duplex"] = re.match(regex, item).group(6).strip()
            item_collected["type"] = re.match(regex, item).group(8).strip()
            info_collected.append(item_collected)
            item_collected = {}
    cmd_output = conn.send_command("show interfaces description").splitlines()
    regex = re.compile(
        r"^([a-zA-Z]+(\d\/){1,2}\d{,2})\s+(admin down|up|down)\s+(up|down)($|.+?$)"
    )
    for item in cmd_output:
        if re.match(regex, item):
            for adict in info_collected:
                if re.match(regex, item).group(1).strip() == adict["intf"]:
                    info_collected[index]["description"] = (
                        re.match(regex, item).group(5).strip()
                    )
                    index += 1
                    break
            else:
                item_collected["hostname"] = hostname.upper()
                item_collected["intf"] = re.match(regex, item).group(1).strip()
                item_collected["status"] = re.match(regex, item).group(4).strip()
                item_collected["speed"] = "n/a(*)"
                item_collected["duplex"] = "n/a(*)"
                item_collected["type"] = "n/a(*)"
                item_collected["description"] = re.match(regex, item).group(5).strip()
                info_collected.insert(index, item_collected)
                index += 1
                item_collected = {}
    return info_collected


def collect_cisco_ios_telnet(conn, hostname):
    info_collected = []
    item_collected = {}
    cmd_output = conn.send_command("show interfaces status").splitlines()
    regex = re.compile(
        r"^([a-zA-Z]+(\d\/){1,2}\d{,2})\s+(|\S.+)(disabled|monitoring|connected|notconn.+?|sfpAbsent)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S.+?)$"
    )
    for item in cmd_output:
        if re.match(regex, item):
            item_collected["hostname"] = hostname.upper()
            item_collected["intf"] = re.match(regex, item).group(1).strip()
            item_collected["status"] = re.match(regex, item).group(4).strip()
            item_collected["speed"] = re.match(regex, item).group(7).strip()
            item_collected["duplex"] = re.match(regex, item).group(6).strip()
            item_collected["type"] = re.match(regex, item).group(8).strip()
            item_collected["description"] = re.match(regex, item).group(3).strip()
            info_collected.append(item_collected)
            item_collected = {}
    return info_collected


def collect_cisco_nxos(conn, hostname):
    info_collected = []
    item_collected = {}
    index = 0
    cmd_output = conn.send_command("show interface status").splitlines()
    regex = re.compile(
        r"^([a-zA-Z]+(\d\/){1,2}\d{,2})\s+(|\S.+)(disabled|monitoring|connected|notconn.+|sfpAbsent|linkFlapE)\s+(trunk|routed|\d{1,4})\s+(\S+)\s+(\S+)\s+(.*)$"
    )
    for item in cmd_output:
        if re.match(regex, item):
            item_collected["hostname"] = hostname.upper()
            item_collected["intf"] = re.match(regex, item).group(1).strip()
            item_collected["status"] = re.match(regex, item).group(4).strip()
            item_collected["speed"] = re.match(regex, item).group(7).strip()
            item_collected["duplex"] = re.match(regex, item).group(6).strip()
            item_collected["type"] = re.match(regex, item).group(8).strip()
            info_collected.append(item_collected)
            item_collected = {}
    cmd_output = conn.send_command("show interface description").splitlines()
    regex = re.compile(r"^([a-zA-Z]+(\d\/){1,2}\d{,2})\s+(\S+)\s+(\S+)\s+(\S.*)$")
    for item in cmd_output:
        if re.match(regex, item):
            info_collected[index]["description"] = (
                re.match(regex, item).group(5).strip()
            )
            index += 1
    return info_collected


def collect_dell_os6(conn, hostname):
    info_collected = []
    item_collected = {}
    index = 0
    cmd_output = conn.send_command("show interfaces status").splitlines()
    regex = re.compile(
        r"^([a-zA-Z]+(\d\/){1,2}\d{,2})\s+(|\S*)\s+(Full|Half|N\/A)\s+(\S+)\s+(Auto|N\/A|Off)\s+(\S+)\s+(.*)$"
    )
    for item in cmd_output:
        if re.match(regex, item):
            item_collected["hostname"] = hostname.upper()
            item_collected["intf"] = re.match(regex, item).group(1).strip()
            item_collected["status"] = re.match(regex, item).group(7).strip()
            item_collected["speed"] = re.match(regex, item).group(5).strip()
            item_collected["duplex"] = re.match(regex, item).group(4).strip()
            item_collected["type"] = "---"
            info_collected.append(item_collected)
            item_collected = {}
    cmd_output = conn.send_command("show interfaces description").splitlines()
    regex = re.compile(r"^([a-zA-Z]+(\d\/){1,2}\d{,2})(.*$)")
    for item in cmd_output:
        if re.match(regex, item):
            info_collected[index]["description"] = (
                re.match(regex, item).group(3).strip()
            )
            index += 1
    return info_collected


def collect_ruckus_fastiron(conn, hostname):
    info_collected = []
    item_collected = {}
    cmd_output = conn.send_command("show interfaces brief wide").splitlines()
    if "Invalid input" in cmd_output[0]:
        cmd_output = conn.send_command("show interfaces brief").splitlines()
    regex = re.compile(
        r"^([0-9\/]+)\s+(Up|Disab.+?|Down|ERR-DIS)\s+([a-zA-Z\/]+)\s+([a-zA-Z0-9\/]+)\s+(\S+)\s+(\S+)\s+(Yes|No|N\/A)\s+(\S+)\s+(\d+)\s+(\w+\.\w+\.\w+|N\/A)($|\s+\S.+?$)"
    )
    for item in cmd_output:
        if re.match(regex, item):
            item_collected["hostname"] = hostname.upper()
            item_collected["intf"] = re.match(regex, item).group(1).strip()
            item_collected["status"] = re.match(regex, item).group(2).strip()
            item_collected["speed"] = re.match(regex, item).group(5).strip()
            item_collected["duplex"] = re.match(regex, item).group(4).strip()
            item_collected["type"] = "---"
            item_collected["description"] = re.match(regex, item).group(11).strip()
            info_collected.append(item_collected)
            item_collected = {}
    return info_collected


def collect_juniper_junos(conn, hostname):
    info_collected = []
    item_collected = {}
    index = 0
    cmd_output = conn.send_command("show interfaces terse").splitlines()
    regex = re.compile(r"^([etx0-9\-\/:]+)\s+(\S+)\s+(\S+)$")
    for item in cmd_output:
        if re.match(regex, item):
            item_collected["hostname"] = hostname.upper()
            item_collected["intf"] = re.match(regex, item).group(1).strip()
            item_collected["status"] = re.match(regex, item).group(3).strip()
            item_collected["speed"] = "---"
            item_collected["duplex"] = "---"
            item_collected["type"] = "---"
            info_collected.append(item_collected)
            item_collected = {}
    cmd_output = conn.send_command("show interfaces descriptions").splitlines()
    regex = re.compile(r"^([etx0-9\-\/:]+)\s+(\S+)\s+(\S+)\s+(\S.+)$")
    for item in info_collected:
        for descr in cmd_output:
            if re.match(regex, descr):
                if item["intf"] == re.match(regex, descr).group(1).strip():
                    info_collected[index]["description"] = (
                        re.match(regex, descr).group(4).strip()
                    )
        index += 1
    return info_collected


def process_device(conn, hostname, type):
    cases = {
        "dell_os9": collect_dell_os9,
        "extreme_nos": collect_extreme_nos,
        "extreme_netiron": collect_extreme_netiron,
        "cisco_ios": collect_cisco_ios,
        "cisco_ios_telnet": collect_cisco_ios_telnet,
        "cisco_nxos": collect_cisco_nxos,
        "dell_os6": collect_dell_os6,
        "ruckus_fastiron": collect_ruckus_fastiron,
        "juniper_junos": collect_juniper_junos,
    }
    return cases[type](conn, hostname)


def main():
    error = False
    consolidate_report = []
    with alive_bar(len(devices), bar="classic", spinner="classic") as bar:
        for key, values in devices.items():
            try:
                conn = conn_device(key, **values.get("conn_info"))
            except Exception:
                error = True
                bar()
                continue
            for item in process_device(
                conn, key, values["conn_info"].get("device_type")
            ):
                consolidate_report.append(item)
            conn.disconnect()
            bar()
    keys = consolidate_report[0].keys()
    with open(
        "".join(["report_", datetime.now().strftime("%Y%m%d-%H%M"), ".csv"]), "a"
    ) as report:
        dict_writer = csv.DictWriter(report, keys)
        dict_writer.writeheader()
        dict_writer.writerows(consolidate_report)
    if error:
        print(f"Ocorreram erros, verfique o arquivo {log_file}")


if __name__ == "__main__":

    log_file = "".join(["error_", datetime.now().strftime("%Y%m%d-%H%M"), ".log"])
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(log_file)
    formatter = logging.Formatter(
        "%(asctime)s : %(levelname)s : %(name)s : %(message)s"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.info("Stating logging...")
    logger.setLevel(logging.WARNING)

    user = input("Usuario: ")
    while not user:
        print("Usuario e mandatorio!")
        user = input("Usuario: ")
    passwd = getpass("Senha: ")
    while not passwd:
        print("Senha e mandatorio!")
        passwd = getpass("Senha: ")
    devices = load_devices("devices.db")

    main()
