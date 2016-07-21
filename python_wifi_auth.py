#!/usr/bin/env python

'''
GPL
2016, Konstantin Shalygin <k0ste@k0ste.ru>
version: 0.1
'''

import os,sys,socket
from optparse import OptionParser
from netaddr import IPAddress, EUI
from pyroute2 import IPRoute
from ipsetpy import ipset_list, ipset_test_entry, ipset_del_entry, ipset_add_entry
from ipsetpy.exceptions import *

message = "Error:"

def start_socket(bind, port, password, max_connections, ipset):
    """
    Start ipv4 tcp socket, and listen for incoming connections.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((bind, port))
    sock.listen(max_connections)
    if bind == "": bind = "*" # for log
    print("Socket is started at {0}:{1}.".format(bind, port))

    try:
        while 1:
            conn, addr = sock.accept()
            print("New connection from: {0}.".format(addr[0]))
            try:
                parse_socket(conn, addr, password, ipset)
            except:
                error = "Error while parse_socket for client: {0}.".format(addr[0])
                sys.stderr.write(error)
                send_answer(conn, addr, "Terminate")
            finally: # if any error, correct close socket
                print("Close connection with: {0}.".format(addr[0]))
                conn.close()
    finally:
        print("Close socket.")
        sock.close()

def send_answer(conn, addr, data="Data is not defined."):
    """
    Method send answer to client.
    """
    utf_data = data.encode("utf-8")
    print("Send to client: {0}, answer: '{1}'".format(addr[0], data))
    conn.send(utf_data + b"\r\n")

def parse_socket(conn, addr, password, ipset):
    """
    Parse data from socket.
    """
    data = b""

    while not b"\r\n" in data: # wait for 1st string
        element = conn.recv(1024)
        if not element: # no data, close this
            break
        else:
            data += element

    if not data:
        return

    parse_data(conn, addr, data, password, ipset) # some data, parse this

def parse_data(conn, addr, data, password, ipset):
    """
    Parse data from socket and calls get or add methods. Use only 1st string.
    If data not have ';' or splitted elemetns not 3 or 4 - return error.
    """

    utf_data = data.decode("utf-8")
    utf_data = utf_data.split("\r\n", 1)[0] # use only 1st string

    if not ";" in utf_data: # separator not found, bullshit data
        error = message + " wrong data format."
        send_answer(conn, addr, error)
    else:
        parse_data = utf_data.split(";")

        if len(parse_data) == 3:
            data_password = parse_data[0]
            data_method = parse_data[1]
            data_ip = parse_data[2]

            verify_password = check_password(password, data_password)

            if data_method == "get" and verify_password:
                worker_get(conn, addr, data_ip)
            else:
                error = message + " wrong password."
                send_answer(conn, addr, error)

        elif len(parse_data) == 4:
            data_password = parse_data[0]
            data_method = parse_data[1]
            data_ip = parse_data[2]
            data_mac = parse_data[3]

            verify_password = check_password(password, data_password)

            if data_method == "add" and verify_password:
                worker_add(conn, addr, data_mac, data_ip, ipset)
            else:
                error = message + " wrong password."
                send_answer(conn, addr, error)

        else:
            error = message + " wrong length of data."
            send_answer(conn, addr, error)

def check_password(server_password, client_password):
    if server_password != client_password:
        return False
    else: return True

def worker_get(conn, addr, data_ip):
    """
    Method return neighbors macaddr if this REACHABLE in ARP cache.
    """
    print("Client: {0}, GET, with ipaddr: {1}".format(addr[0], data_ip))
    check_ip = check_ipaddr(data_ip)

    if check_ip:
        get_mac = get_ne_mac(data_ip)

        if get_mac:
            send_answer(conn, addr, get_mac)
        elif get_mac == None:
            error = message + " macaddr for ipaddr not found."
            send_answer(conn, addr, error)

    else:
        error = message + " ipaddr is not valid."
        send_answer(conn, addr, error)

def worker_add(conn, addr, data_mac, data_ip, ipset):
    """
    Method add ipaddr+macaddr entry to ipset.
    Before add set, set checked for present state by ipaddres, because
    set may have old client macaddr.
    """
    print("Client: {0}, ADD, with ipaddr: {1}, macaddr: {2}".format(addr[0], data_ip, data_mac))

    check_ip = check_ipaddr(data_ip)
    check_mac = check_macaddr(data_mac)

    if check_ip and check_mac: #  when ipaddr and macaddr valid - make entry for ipset
        entry = data_ip + ',' + data_mac
        check_entry = check_ipset_entry(ipset, data_ip)

        if check_entry:
            delete = del_ipset_entry(ipset, data_ip)
            add = add_ipset_entry(ipset, entry)

            if delete and add: send_answer(conn, addr, entry)
        else:
            add_ipset_entry(ipset, entry)
            send_answer(conn, addr, entry)
    else:
        error = message + " ipaddr or macaddr not valid."
        send_answer(conn, addr, error)

def get_ne_mac(ipaddr):
    """
    Get neighbors macaddr via netlink.
    """
    iproute = IPRoute()
    try:
        neighbour_mac = iproute.get_neighbours(family=socket.AF_INET, dst=ipaddr)

        if len(neighbour_mac) != 0:
            mac = ([mac.get_attr('NDA_LLADDR') for mac in neighbour_mac][0])
            return mac
        else: return

        iproute.close()
    except:
        print("Can't get macaddr for ipaddr: {0}.".format(ipaddr))

def check_ipaddr(ipaddr):
    """
    Validate ipaddr via netaddr library.
    """
    ipaddr_result = IPAddress(ipaddr)
    try:
        if ipaddr_result:
            return True
        else: return False
    except:
        print("Can't check ipaddr: {0}.".format(ipaddr))

def check_macaddr(macaddr):
    """
    Validate macaddr via netaddr library.
    """
    try:
        macaddr_result = EUI(macaddr)
        if macaddr_result:
            return True
        else: return False
    except:
        print("Can't check macaddr: {0}.".format(macaddr))

def check_ipset_state(ipset):
    """
    Verify ipset is created.
    """
    try:
        ipset_result = ipset_list(set_name=ipset)
        return True
    except IpsetSetNotFound:
        error = "Can't found ipset: {0}, create ipset before use.".format(ipset)
        sys.stderr.write(error)
        return False

def check_ipset_entry(ipset, ipaddr):
    """
    Check ipaddr in ipset, return boolean result.
    """
    try:
        test = ipset_test_entry(ipset, ipaddr)
        if test:
            print("Entry: {0} is present in ipset: {1}.".format(ipaddr, ipset))
        else:
            print("Entry: {0} is absent in ipset: {1}.".format(ipaddr, ipset))
        return test
    except:
        print("Can't test entry: {0}, for set: {1}.".format(ipaddr, ipset))
        return

def del_ipset_entry(ipset, ipaddr):
    """
    Delete ipaddr from ipset.
    """
    try:
        delete = ipset_del_entry(ipset, ipaddr)
        print("Entry: {0} is deleted from ipset: {1}.".format(ipaddr, ipset))
        return True
    except IpsetError:
        print("Can't delete entry: {0} from ipset: {1}.".format(ipaddr, ipset))
        return

def add_ipset_entry(ipset, entry):
    """
    Add entry to ipset. Format: 'ipaddr,macaddr'.
    """
    try:
        ipset_add_entry(ipset, entry)
        print("Entry: {0} is accepted to ipset: {1}.".format(entry, ipset))
        return True
    except IpsetError:
        print("Can't add entry: {0} to ipset: {1}.".format(entry, ipset))
        return

def dry_run(bind, port, password, max_connections, ipset):
    e = check_ipset_state(ipset)
    if e:
        start_socket(bind, port, password, max_connections, ipset)
    else:
        raise SystemExit

def main():
    parser = OptionParser(usage='%prog -i ipset_name', version='%prog 0.1')
    parser.add_option('-b', '--bind', type='string', dest='socket_bind', default="", help='Bind to address [default: all ipv4]')
    parser.add_option('-p', '--port', type='int', dest='socket_port', default='54321', help='Bind to port [default: %default]')
    parser.add_option('-m', '--max-connections', type='int', dest='socket_max_connections', default='10', help='Max connections to socket [default: %default]')
    parser.add_option('-P', '--password', type='string', dest='socket_password', default='admin', help='With listen password [default: %default]')
    parser.add_option('-i', '--ipset', type='string', dest='ipset', help='Work with this ipset')
    (options, args) = parser.parse_args()

    if not options.ipset:
        parser.print_help()
        raise SystemExit

    dry_run(options.socket_bind, options.socket_port, options.socket_password, options.socket_max_connections, options.ipset)

if __name__ == "__main__":
  main()
