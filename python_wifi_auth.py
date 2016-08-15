#!/usr/bin/python -u
# -*- coding: utf-8 -*-

"""
GPL
2016, Konstantin Shalygin <k0ste@k0ste.ru>
"""

import os,sys
import socket
import logging
from optparse import OptionParser
from netaddr import IPAddress, EUI, AddrFormatError
from pyroute2 import IPRoute
from ipsetpy import ipset_list, ipset_test_entry, ipset_del_entry, ipset_add_entry
from ipsetpy.exceptions import *

class SmsAuth(object):
    def dry_run(self):
        """
        Before start socket - verify that ipset is present.
        """
        ipset_state = self.check_ipset_state()
        if self.socket_bind != "": self.socket_bind = self.get_iface_ipaddr()

        if ipset_state and (self.socket_bind or self.socket_bind == ""): # ipset ok & iface ok, start socket
            self.start_socket()
        else:
            sys.exit(2)

    def logger(self):
        """
        Console Handler - for output to stdout.
        """
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        log_formatter = logging.Formatter(fmt="%(message)s",
                                          datefmt="%a %b %d %H:%M:%S %Z %Y") # Date in Linux format

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(log_formatter)
        root_logger.addHandler(console_handler)

    def get_ne_mac(self, ipaddr):
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
                logging.info("Can't find macaddr for ipaddr '{0}'.".format(ipaddr))
                return False
        except:
            logging.error("Can't get macaddr for ipaddr '{0}'.".format(ipaddr))
        finally:
            iproute.close()

    def get_iface_ipaddr(self):
        """
        Method return ipaddres for desired interface.
        """
        try:
            iproute = IPRoute()
            iface_ipaddr = iproute.get_addr(family=socket.AF_INET, label=self.socket_bind)

            if len(iface_ipaddr) != 0:
                ipaddr = ([ipaddr.get_attr('IFA_ADDRESS') for ipaddr in iface_ipaddr][0])
                return ipaddr
            else:
                logging.error("Can't found any ipaddr on interface '{0}'.".format(self.socket_bind))
                return False
        except:
            logging.error("Can't get any ipaddr on interface '{0}'.".format(self.socket_bind))
        finally:
            iproute.close()

    def start_socket(self):
        """
        Start ipv4 tcp socket, and listen for incoming connections.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse port, avoid OSError 48
        sock.bind((self.socket_bind, self.socket_port))
        sock.listen(self.socket_max_connections)
        if self.socket_bind == "": self.socket_bind = "*" # for log
        logging.info("Socket is started at {0}:{1}.".format(self.socket_bind, self.socket_port))

        try:
            while 1:
                conn, addr = sock.accept()
                logging.info("New connection from '{0}'.".format(addr[0]))
                try:
                    self.parse_socket(conn, addr)
                except:
                    logging.error("Error while parse_socket for client '{0}'.".format(addr[0]))
                    self.send_answer(conn, addr, data="Terminate.")
                finally: # if any error, correct close socket
                    logging.info("Close connection with '{0}'.".format(addr[0]))
                    conn.close()
        finally:
            logging.info("Close socket.")
            sock.close()

    def send_answer(self, conn, addr, data="Data is not defined."):
        """
        Method send answer to client.
        """
        utf_data = data.encode("utf-8")
        logging.info("Send to client '{0}', answer '{1}'.".format(addr[0], data))
        conn.send(utf_data + b"\r\n")

    def parse_socket(self, conn, addr):
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

        self.parse_data(conn, addr, data) # some data, parse this

    def parse_data(self, conn, addr, data):
        """
        Parse data from socket and calls get or add methods. Use only 1st string.
        If data not have ';' or splitted elemetns not 4 or 5 - return error.
        """
        utf_data = data.decode("utf-8")
        utf_data = utf_data.split("\r\n", 1)[0] # use only 1st string

        if not ";" in utf_data: # separator not found, bullshit data
            self.send_answer(conn, addr, data="Error: wrong data format.")
        else:
            parse_data = utf_data.split(";")

            if len(parse_data) == 4:
                data_password = parse_data[0]
                data_method = parse_data[1]
                data_ip = parse_data[2]

                verify_password = self.check_password(self.socket_password, data_password)

                if data_method == "get" and verify_password:
                    self.worker_get(conn, addr, data_ip)
                else:
                    self.send_answer(conn, addr, data="Error: wrong password.")

            elif len(parse_data) == 5:
                data_password = parse_data[0]
                data_method = parse_data[1]
                data_ip = parse_data[2]
                data_mac = parse_data[3]

                verify_password = self.check_password(self.socket_password, data_password)

                if data_method == "add" and verify_password:
                    self.worker_add(conn, addr, data_mac, data_ip)
                else:
                    self.send_answer(conn, addr, data="Error: wrong password.")

            else:
                self.send_answer(conn, addr, data="Error: wrong length of data.")

    def check_password(self, server_password, client_password):
        if server_password != client_password:
            return False
        else: return True

    def worker_get(self, conn, addr, data_ip):
        """
        Method return neighbors macaddr if this REACHABLE in ARP cache.
        """
        logging.info("Client '{0}', GET, with ipaddr '{1}'.".format(addr[0], data_ip))
        check_ip = self.validate_ipaddr(data_ip)

        if check_ip:

            get_mac = self.get_ne_mac(data_ip)
            if get_mac:
                self.send_answer(conn, addr, get_mac)
            else:
                self.send_answer(conn, addr, data="Error: macaddr for ipaddr not found.")

        else:
            self.send_answer(conn, addr, data="Error: ipaddr is not valid.")

    def worker_add(self, conn, addr, data_mac, data_ip):
        """
        Method add ipaddr+macaddr entry to ipset.
        Before add set, set checked for present state by ipaddres, because
        set may have old client macaddr.
        """
        logging.info("Client '{0}', ADD, with ipaddr '{1}' and macaddr '{2}'.".format(addr[0], data_ip, data_mac))

        check_ip = self.validate_ipaddr(data_ip)
        check_mac = self.validate_macaddr(data_mac)

        if check_ip and check_mac: #  when ipaddr and macaddr valid - make entry for ipset
            entry = data_ip + ',' + data_mac
            check_entry = self.check_ipset_entry(data_ip)

            if check_entry:
                delete = self.del_ipset_entry(data_ip)
                add = self.add_ipset_entry(entry)

                if delete and add: self.send_answer(conn, addr, entry)
            else:
                self.add_ipset_entry(entry)
                self.send_answer(conn, addr, entry)
        else:
            self.send_answer(conn, addr, data="Error: ipaddr or macaddr not valid.")

    def get_ne_mac(self, ipaddr):
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
            logging.error("Can't get macaddr for ipaddr '{0}'.".format(ipaddr))

    def validate_ipaddr(self, ipaddr):
        """
        Validate ipaddr via netaddr library.
        """
        try:
            ipaddr_result = IPAddress(ipaddr)
            if ipaddr_result: return True
        except AddrFormatError:
            logging.error("Can't validate ipaddr '{0}'.".format(ipaddr))
            return False

    def validate_macaddr(self, macaddr):
        """
        Validate macaddr via netaddr library.
        """
        try:
            macaddr_result = EUI(macaddr)
            if macaddr_result: return True
        except AddrFormatError:
            logging.error("Can't validate macaddr '{0}'.".format(macaddr))
            return False

    def check_ipset_state(self):
        """
        Verify ipset is created.
        """
        try:
            ipset_result = ipset_list(set_name=self.ipset)
            return True
        except IpsetSetNotFound:
            logging.error("Can't found ipset '{0}', create ipset before use.".format(self.ipset))
            return False

    def check_ipset_entry(self, ipaddr):
        """
        Check ipaddr in ipset, return boolean result.
        """
        try:
            test = ipset_test_entry(self.ipset, ipaddr)
            if test: logging.info("Entry '{0}' is present in ipset '{1}'.".format(ipaddr, self.ipset))
            else: logging.info("Entry '{0}' is absent in ipset '{1}'.".format(ipaddr, self.ipset))
            return test
        except:
            logging.error("Can't test entry '{0}', for set '{1}'.".format(ipaddr, self.ipset))
            return

    def del_ipset_entry(self, ipaddr):
        """
        Delete ipaddr from ipset.
        """
        try:
            delete = ipset_del_entry(self.ipset, ipaddr)
            logging.info("Entry '{0}' is deleted from ipset '{1}'.".format(ipaddr, self.ipset))
            return True
        except IpsetError:
            logging.error("Can't delete entry '{0}' from ipset '{1}'.".format(ipaddr, self.ipset))
            return

    def add_ipset_entry(self, entry):
        """
        Add entry to ipset. Format: 'ipaddr,macaddr'.
        """
        try:
            ipset_add_entry(self.ipset, entry)
            logging.info("Entry '{0}' is accepted to ipset '{1}'.".format(entry, self.ipset))
            return True
        except IpsetError:
            logging.error("Can't add entry '{0}' to ipset '{1}'.".format(entry, self.ipset))
            return

    def __init__(self):
        parser = OptionParser(usage="%prog -i ipset_name -b eth0 -p 4233 -P password", version="%prog 0.3")
        parser.add_option("-b", "--bind", type="string", dest="socket_bind", default="", help="Bind interface [default: all ipv4]")
        parser.add_option("-p", "--port", type="int", dest="socket_port", default="4233", help="Bind to port [default: %default]")
        parser.add_option("-m", "--max-connections", type="int", dest="socket_max_connections", default="10", help="Max connections to socket [default: %default]")
        parser.add_option("-P", "--password", type="string", dest="socket_password", help="With listen password")
        parser.add_option("-i", "--ipset", type="string", dest="ipset", help="Work with this ipset")
        (options, args) = parser.parse_args()

        if (not options.ipset or not options.socket_password):
            parser.print_help()
            sys.exit(1)

        self.logger()
        self.socket_bind = options.socket_bind
        self.socket_port = options.socket_port
        self.socket_password = options.socket_password
        self.socket_max_connections = options.socket_max_connections
        self.ipset = options.ipset

def main():
    sms_auth = SmsAuth()
    sms_auth.dry_run()

if __name__ == "__main__":
    main()
