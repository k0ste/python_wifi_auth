#!/usr/bin/python -u

"""
GPL
2016, Konstantin Shalygin <k0ste@k0ste.ru>
version: 0.2
"""

import os,sys,socket
from optparse import OptionParser
from netaddr import IPAddress, EUI, AddrFormatError
from pyroute2 import IPRoute
from ipsetpy import ipset_list, ipset_test_entry, ipset_del_entry, ipset_add_entry
from ipsetpy.exceptions import *

def dry_run(bind, port, password, max_connections, ipset):
    """
    Before start socket - verify that ipset is present.
    """
    ipset_state = check_ipset_state(ipset)
    if bind != "": bind = get_iface_ipaddr(bind)

    if ipset_state and (bind or bind == ""): # ipset ok & iface ok, start socket
        start_socket(bind, port, password, max_connections, ipset)
    else:
        sys.exit(2)

def get_ne_mac(ipaddr):
    """
    Get neighbors macaddr via netlink.
    """
    try:
        iproute = IPRoute()
        neighbour_mac = iproute.get_neighbours(family=socket.AF_INET, dst=ipaddr)

        if len(neighbour_mac) != 0:
            mac = ([mac.get_attr('NDA_LLADDR') for mac in neighbour_mac][0])
            return mac
        else:
            sys.stdout.write("Can't found macaddr for ipaddr: {0}.\n".format(ipaddr))
            return False
    except:
        sys.stderr.write("Can't get macaddr for ipaddr: {0}.\n".format(ipaddr))
    finally:
        iproute.close()

def get_iface_ipaddr(bind):
    """
    Method return ipaddres for desired interface.
    """
    try:
        iproute = IPRoute()
        iface_ipaddr = iproute.get_addr(family=socket.AF_INET, label=bind)

        if len(iface_ipaddr) != 0:
            ipaddr = ([ipaddr.get_attr('IFA_ADDRESS') for ipaddr in iface_ipaddr][0])
            return ipaddr
        else:
            sys.stderr.write("Can't found any ipaddr on interface: {0}.\n".format(bind))
            return False
    except:
        sys.stderr.write("Can't get any ipaddr on interface: {0}.\n".format(bind))
    finally:
        iproute.close()

def start_socket(bind, port, password, max_connections, ipset):
    """
    Start ipv4 tcp socket, and listen for incoming connections.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse port, avoid OSError 48
    sock.bind((bind, port))
    sock.listen(max_connections)
    if bind == "": bind = "*" # for log
    sys.stdout.write("Socket is started at {0}:{1}.\n".format(bind, port))

    try:
        while 1:
            conn, addr = sock.accept()
            sys.stdout.write("New connection from: {0}.\n".format(addr[0]))
            try:
                parse_socket(conn, addr, password, ipset)
            except:
                sys.stderr.write("Error while parse_socket for client: {0}.\n".format(addr[0]))
                send_answer(conn, addr, data="Terminate.")
            finally: # if any error, correct close socket
                sys.stdout.write("Close connection with: {0}.\n".format(addr[0]))
                conn.close()
    finally:
        sys.stdout.write("Close socket.\n")
        sock.close()

def send_answer(conn, addr, data="Data is not defined."):
    """
    Method send answer to client.
    """
    utf_data = data.encode("utf-8")
    sys.stdout.write("Send to client: {0}, answer: '{1}'\n".format(addr[0], data))
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
    If data not have ';' or splitted elemetns not 4 or 5 - return error.
    """
    utf_data = data.decode("utf-8")
    utf_data = utf_data.split("\r\n", 1)[0] # use only 1st string

    if not ";" in utf_data: # separator not found, bullshit data
        send_answer(conn, addr, data="Error: wrong data format.")
    else:
        parse_data = utf_data.split(";")

        if len(parse_data) == 4:
            data_password = parse_data[0]
            data_method = parse_data[1]
            data_ip = parse_data[2]

            verify_password = check_password(password, data_password)

            if data_method == "get" and verify_password:
                worker_get(conn, addr, data_ip)
            else:
                send_answer(conn, addr, data="Error: wrong password.")

        elif len(parse_data) == 5:
            data_password = parse_data[0]
            data_method = parse_data[1]
            data_ip = parse_data[2]
            data_mac = parse_data[3]

            verify_password = check_password(password, data_password)

            if data_method == "add" and verify_password:
                worker_add(conn, addr, data_mac, data_ip, ipset)
            else:
                send_answer(conn, addr, data="Error: wrong password.")

        else:
            send_answer(conn, addr, data="Error: wrong length of data.")

def check_password(server_password, client_password):
    if server_password != client_password:
        return False
    else: return True

def worker_get(conn, addr, data_ip):
    """
    Method return neighbors macaddr if this REACHABLE in ARP cache.
    """
    sys.stdout.write("Client: {0}, GET, with ipaddr: {1}.\n".format(addr[0], data_ip))
    check_ip = validate_ipaddr(data_ip)

    if check_ip:

        get_mac = get_ne_mac(data_ip)
        if get_mac:
            send_answer(conn, addr, get_mac)
        else:
            send_answer(conn, addr, data="Error: macaddr for ipaddr not found.")

    else:
        send_answer(conn, addr, data="Error: ipaddr is not valid.")

def worker_add(conn, addr, data_mac, data_ip, ipset):
    """
    Method add ipaddr+macaddr entry to ipset.
    Before add set, set checked for present state by ipaddres, because
    set may have old client macaddr.
    """
    sys.stdout.write("Client: {0}, ADD, with ipaddr: {1}, macaddr: {2}.\n".format(addr[0], data_ip, data_mac))

    check_ip = validate_ipaddr(data_ip)
    check_mac = validate_macaddr(data_mac)

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
        send_answer(conn, addr, data="Error: ipaddr or macaddr not valid.")

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
        sys.stderr.write("Can't get macaddr for ipaddr: {0}.\n".format(ipaddr))

def validate_ipaddr(ipaddr):
    """
    Validate ipaddr via netaddr library.
    """
    try:
        ipaddr_result = IPAddress(ipaddr)
        if ipaddr_result: return True
    except AddrFormatError:
        sys.stderr.write("Can't validate ipaddr: {0}.\n".format(ipaddr))
        return False

def validate_macaddr(macaddr):
    """
    Validate macaddr via netaddr library.
    """
    try:
        macaddr_result = EUI(macaddr)
        if macaddr_result: return True
    except AddrFormatError:
        sys.stderr.write("Can't validate macaddr: {0}.\n".format(macaddr))
        return False

def check_ipset_state(ipset):
    """
    Verify ipset is created.
    """
    try:
        ipset_result = ipset_list(set_name=ipset)
        return True
    except IpsetSetNotFound:
        sys.stderr.write("Can't found ipset: {0}, create ipset before use.\n".format(ipset))
        return False

def check_ipset_entry(ipset, ipaddr):
    """
    Check ipaddr in ipset, return boolean result.
    """
    try:
        test = ipset_test_entry(ipset, ipaddr)
        if test: sys.stdout.write("Entry: {0} is present in ipset: {1}.\n".format(ipaddr, ipset))
        else: sys.stdout.write("Entry: {0} is absent in ipset: {1}.\n".format(ipaddr, ipset))
        return test
    except:
        sys.stderr.write("Can't test entry: {0}, for set: {1}.\n".format(ipaddr, ipset))
        return

def del_ipset_entry(ipset, ipaddr):
    """
    Delete ipaddr from ipset.
    """
    try:
        delete = ipset_del_entry(ipset, ipaddr)
        sys.stdout.write("Entry: {0} is deleted from ipset: {1}.\n".format(ipaddr, ipset))
        return True
    except IpsetError:
        sys.stderr.write("Can't delete entry: {0} from ipset: {1}.\n".format(ipaddr, ipset))
        return

def add_ipset_entry(ipset, entry):
    """
    Add entry to ipset. Format: 'ipaddr,macaddr'.
    """
    try:
        ipset_add_entry(ipset, entry)
        sys.stdout.write("Entry: {0} is accepted to ipset: {1}.\n".format(entry, ipset))
        return True
    except IpsetError:
        sys.stderr.write("Can't add entry: {0} to ipset: {1}.\n".format(entry, ipset))
        return

def main():
    parser = OptionParser(usage='%prog -i ipset_name -b eth0 -p 4233 -P password', version='%prog 0.2')
    parser.add_option('-b', '--bind', type='string', dest='socket_bind', default='', help='Bind interface [default: all ipv4]')
    parser.add_option('-p', '--port', type='int', dest='socket_port', default='4233', help='Bind to port [default: %default]')
    parser.add_option('-m', '--max-connections', type='int', dest='socket_max_connections', default='10', help='Max connections to socket [default: %default]')
    parser.add_option('-P', '--password', type='string', dest='socket_password', default='', help='With listen password')
    parser.add_option('-i', '--ipset', type='string', dest='ipset', help='Work with this ipset')
    (options, args) = parser.parse_args()

    if (not options.ipset or not options.socket_password):
        parser.print_help()
        sys.exit(2)

    dry_run(options.socket_bind, options.socket_port, options.socket_password, options.socket_max_connections, options.ipset)

if __name__ == "__main__":
  main()
