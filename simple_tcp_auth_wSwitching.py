from netaddr import IPAddress
from ryu.app.portknock_rest_server import Portknock_Server
from ryu.app.simple_hubswitch_class import SimpleHubSwitch  # packet switching logic
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls
)
from ryu.lib.packet import (
    in_proto,  # ipv4 layer 3 protocols
    packet,
    ethernet,
    ether_types,
    ipv4,
    ipv6,
    arp as ARP,
    tcp as TCP
)
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser


class Port_Knocking(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(Port_Knocking, self).__init__(*args, **kwargs)

        # record of server location on each switch
        self.datapaths = {}  # dpid -> datapath object
        self.server_port = {}  # dpid -> port number on switch to reach server

        ## server location, MAC address that access is restricted to (the 'server')
        self.server_mac_address = [
            '00:00:00:00:00:02',
            '00:00:00:00:00:03'
        ]

        ## key config
        self.auth_port = 1332  # TCP port to initiate authentication key
        self.active_keys = {
            "10.0.0.2": {
                "current_key": -1,
                "current_seq": -1,
                "keys": {
                    1000: [1000, 1001, 1002],
                    1001: [1001, 1002, 1003]
                },
                "authenticated_hosts": {}
            },
            "10.0.0.3": {
                "current_key": -1,
                "current_seq": -1,
                "keys": {
                    1000: [1000, 1001, 1002],
                    1001: [1001, 1002, 1003]
                },
                "authenticated_hosts": {}
            }
        }
        self.active_keys_v6 = {
            str(IPAddress('fe80::200:ff:fe00:2')): {
                "current_key": -1,
                "current_seq": -1,
                "keys": {
                    1000: [1000, 1001, 1002],
                    1001: [1001, 1002, 1003]
                },
                "authenticated_hosts": {},
            },
            str(IPAddress('fe80::200:ff:fe00:3')): {
                "current_key": -1,
                "current_seq": -1,
                "keys": {
                    1000: [1000, 1001, 1002],
                    1001: [1001, 1002, 1003]
                },
                "authenticated_hosts": {},
            }
        }
        ## host records
        self.authing_hosts = {}  # Hosts currently entering keys; host_ip -> key buffer s.t. key buffer [port0==keyID,port1,port2,port3,..]
        self.blocked_hosts = {}  # Hosts who entered incorrect key; host_ip -> timeout ## may not implement atm
        self.default_time = 1800  # seconds till invalid (3600 == one hour)

        # get/register other classes
        self.switching = SimpleHubSwitch()
        wsgi = kwargs['wsgi']
        wsgi.register(Portknock_Server, {'port_knocking': self})

        # testing key TODO
        # self.add_auth_key([
        #     {"value": 1489, "seq": 0, "port": 1489},
        #     {"value": 15961, "seq": 1, "port": 32345},
        #     {"value": 8637, "seq": 2, "port": 41405},
        #     {"value": 2929, "seq": 3, "port": 52081}])
        # self.load_keys_from_file('test_keys.txt')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Runs when switches handshake with controller
          installs a default flow to out:CONTROLLER"""
        datapath = ev.msg.datapath

        self.datapaths[datapath.id] = datapath
        self.switching.switch_features_handler(ev)

        self.install_server_blocking_flows(datapath)
        self.install_auth_init_flow(datapath)

    def load_keys_from_file(self, filename):
        """ Loads a list of keys from file
              Keys are separated by line, values by commas """
        print('(AUTH-key file) loading from file')

        def convert_to_key(port_num):
            port_num = int(port_num)
            i, k = port_to_parts(port_num, self.seq_size)
            return {'value': k, 'seq': i, 'port': port_num}

        with open(filename, 'r') as infile:
            for line in infile:
                self.add_auth_key(map(convert_to_key, line.split(',')))

    def add_auth_key(self, which_host, key_list):
        # TODO
        if self.active_keys.get(which_host) is None:
            self.active_keys[which_host] = {
                "current": "",
                "keys": {}
            }
        self.active_keys[which_host]["keys"][key_list[0]] = key_list

    def install_server_blocking_flows(self, datapath):
        ''' Blocking IP access to the server and allowing ARP '''
        print('(AUTH-install) installing %d\'s server block flows' % datapath.id)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        action_block = []  # empty == drop

        # L2 block
        for addr in self.server_mac_address:
            match_mac = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_dst=addr)
            add_flow(datapath, 1, match_mac, action_block)

        # L3 block
        for addr in self.active_keys:
            match_ipv4 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=IPAddress(addr))
            add_flow(datapath, 1, match_ipv4, action_block)

        for addr in self.active_keys_v6:
            match_ipv6 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6, ipv6_dst=IPAddress(addr))
            add_flow(datapath, 1, match_ipv6, action_block)

    def install_auth_init_flow(self, datapath):
        '''  Install rule for matching for the TCP auth init packet '''
        print('(AUTH-install) installing %d\'s knock init flows' % datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        action_packet_in = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        for addr in self.active_keys:
            # send TCP on port self.auth_port to controller
            match_tcp_auth_ipv4 = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,
                    ipv4_dst=IPAddress(addr), tcp_dst=self.auth_port)
            # add a flow for auth init packet capture
            add_flow(datapath, 2, match_tcp_auth_ipv4, action_packet_in)

        for addr in self.active_keys_v6:
            # send TCP on port self.auth_port to controller
            match_tcp_auth_ipv6 = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,
                    ipv6_dst=IPAddress(addr), tcp_dst=self.auth_port)
            # add a flow for auth init packet capture
            add_flow(datapath, 2, match_tcp_auth_ipv6, action_packet_in)

    def auth_host(self, src_ip, dst_ip, datapath):
        ''' Allows given host to access the server '''

        action_allow_to_server = [ofproto_v1_3_parser.OFPActionOutput(self.server_port[datapath.id])]

        # add rules for mac to access server
        match_ipv4 = ofproto_v1_3_parser.OFPMatch()
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, ether_types.ETH_TYPE_IP)
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC, int(IPAddress(src_ip)))
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_DST, int(IPAddress(dst_ip)))
        add_flow(datapath, 3, match_ipv4, action_allow_to_server)

        print ('(AUTH-auth authenticated id:%s on dpid:%s' % (src_ip, datapath.id))

    def match_key(self, src_ip, dst_ip, dst_port, datapath):
        ''' Matches the sequence of knocks against buffered key '''

        print('dst port %d' % dst_port)
        key_id = self.active_keys[dst_ip]["current_key"]
        idx = self.active_keys[dst_ip]["current_seq"]

        if key_id == -1:
            # first sequence key
            if dst_port in self.active_keys[dst_ip]["keys"]:
                self.active_keys[dst_ip]["current_key"] = key_id = dst_port
                self.active_keys[dst_ip]["current_seq"] = idx = 0
            else:
                print('key not yet defined')
                return  # don't accept anything until key is selected

        key_val = self.active_keys[dst_ip]["keys"][key_id][idx]
        key_length = len(self.active_keys[dst_ip]["keys"][key_id])

        if idx > 0:
            key_val_last = self.active_keys[dst_ip]["keys"][key_id][idx - 1]
        else:
            key_val_last = -1

        if dst_port == key_val_last:
            print('duplicate %d->%d' % (idx - 1, dst_port))
            return
        elif dst_port != key_val:
            self.active_keys[dst_ip]["current_key"] = -1
            self.active_keys[dst_ip]["current_seq"] = -1
            self.remove_key_from(src_ip)
            self.invalid_key('value %d doesn\'t match key idx %d of key %d (%d)'
                             % (dst_port, idx + 1, key_length, key_val))
            return

        # dst_port == key_val
        print('(AUTH-buffered) %s -> %s length: %d/%d (%d)' % (src_ip, dst_ip, idx + 1, key_length, key_val))

        if idx + 1 == key_length:
            # key complete, authorise IP address to access server
            print('(AUTH-seq complete) ip:%s' % src_ip)

            # add host to authenticated hosts
            self.active_keys[dst_ip]["authenticated_hosts"][src_ip] = 10000

            # tidy up
            self.active_keys[dst_ip]["current_key"] = -1
            self.active_keys[dst_ip]["current_seq"] = -1
            self.remove_key_from(src_ip)

            # install flows to access server
            self.auth_host(src_ip, dst_ip, datapath)
        else:
            self.authing_hosts[src_ip] = {}
            self.active_keys[dst_ip]["current_seq"] = idx + 1

    def invalid_key(self, msg=''):
        # TODO: block for a few seconds
        # TODO: release authing key from host?
        print('(AUTH-invalid key) %s' % msg)

    def remove_key_from(self, src_ip):
        ''' expired keys are disassociated from authing host '''
        del self.authing_hosts[src_ip]

    def initialise_host_auth(self, src_ip, dst_ip, datapath):
        print ('(AUTH-auth init) received init from %s' % src_ip)
        self.authing_hosts[src_ip] = {}  # empty key buffer

        # install flow, fwd all tcp to controller
        action_fwd_to_controller = [ofproto_v1_3_parser.OFPActionOutput(ofproto_v1_3.OFPP_CONTROLLER)]
        match_ipv4 = ofproto_v1_3_parser.OFPMatch()
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, ether_types.ETH_TYPE_IP)
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC, int(IPAddress(src_ip)))
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_DST, int(IPAddress(dst_ip)))

        add_flow(datapath, 3, match_ipv4, action_fwd_to_controller)

    def remove_auth_flows(self, src_ip, dst_ip):
        """ removes the flows that capture knock sequence
                (identified with src_ip and priority) """
        match_ipv4 = ofproto_v1_3_parser.OFPMatch()
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, ether_types.ETH_TYPE_IP)
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC, int(IPAddress(src_ip)))
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_DST, int(IPAddress(dst_ip)))

        for id in self.datapaths:
            delete_flow(self.datapaths[id], 3, match_ipv4)

    def remove_host_access(self, src_ip, dst_ip):
        """ Revokes access to server for an authorised host """

        if src_ip not in self.active_keys[dst_ip]["authenticated_hosts"]:
            return False

        print('removing %s from auth hosts' % src_ip)
        del self.active_keys[dst_ip]["authenticated_hosts"][src_ip]
        self.remove_auth_flows(src_ip, dst_ip)

        return True

    def set_datapath_svr_port(self, dpid, in_port):
        if dpid in self.server_port and self.server_port[dpid] == in_port:
            # already set and no change
            return

        print '(AUTH-packet_in) %d\'s server_port: %d' % (dpid, in_port)
        self.server_port[dpid] = in_port

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''Listen for auth packets
            and server announcement'''

        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        eth_type = eth.ethertype

        # capture auth packets
        if eth_type == ether_types.ETH_TYPE_IP:
            # if TCP and dst is server
            # ipv4
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            if ip.proto == in_proto.IPPROTO_TCP and ip.dst in self.active_keys:
                tcp = pkt.get_protocols(TCP.tcp)[0]

                if ip.src in self.active_keys[ip.dst][
                    "authenticated_hosts"]:  # likely from another switch, so needs to have flow to server installed
                    self.auth_host(ip.src, ip.dst, dp)

                elif ip.src in self.authing_hosts:
                    self.match_key(ip.src, ip.dst, tcp.dst_port, dp)

                elif tcp.dst_port == self.auth_port:
                    # install key matching flows for host
                    self.initialise_host_auth(ip.src, ip.dst, dp)
                return  # avoid installing flow (block TCP traffic to server)

            if ip.dst in self.active_keys:
                # avoids controller forwarding on other IP packets while ALL TO CONTROLLER is active
                return

        # ipv6 to server, block from switch
        if eth_type == ether_types.ETH_TYPE_IPV6:
            ip = pkt.get_protocols(ipv6.ipv6)[0]
            if ip.dst in self.active_keys_v6:
                return

        # if from server, get port_id of server (reply from ARP will trigger this)
        if eth.src in self.server_mac_address:
            self.set_datapath_svr_port(dp.id, msg.match['in_port'])

        # do regular switching
        self.switching.packet_in_handler(ev)


def add_flow(datapath, priority, match, actions, buffer_id=None):
    '''Adds this flow to the given datapath'''

    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    if buffer_id:
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                priority=priority, match=match, instructions=inst)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
    # print("(AUTH-add flow): %s %s" % (match, actions))
    datapath.send_msg(mod)


def delete_flow(datapath, priority, match):
    ''' This method is stolen from Jarrod :P '''
    print('delete flow %s' % match)
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    command = ofproto.OFPFC_DELETE
    mod = parser.OFPFlowMod(datapath=datapath, command=command,
                            priority=priority, match=match,
                            out_port=ofproto.OFPP_ANY,
                            out_group=ofproto.OFPG_ANY)
    datapath.send_msg(mod)
