from Sniffer import Sniffer
from scapy.all import *
from scapy.layers import http


def find_streams(packets: PacketList):
    streams = []
    for i in packets:
        src_mac = i.getfieldval('src')
        dst_mac = i.getfieldval('dst')
        src = src_mac
        dst = dst_mac
        datagram = i.payload
        if datagram is not None:
            src_ip = datagram.getfieldval('src')
            dst_ip = datagram.getfieldval('dst')
            segment = i.payload
            src += ' ' + src_ip
            dst += ' ' + dst_ip
            if segment is not None:
                src_port = segment.getfieldval('sport')
                dst_port = segment.getfieldval('dport')
                src += ' {}'.format(src_port)
                dst += ' {}'.format(dst_port)
        stream = {src, dst}
        if stream not in streams:
            streams.append(stream)

    return streams


def find_tcp_streams(packets: PacketList):
    streams = []
    for i in packets:
        if i.haslayer('TCP') == 0:
            continue
        src_mac = i.getfieldval('src')
        dst_mac = i.getfieldval('dst')
        src = src_mac
        dst = dst_mac
        datagram = i.payload
        if datagram is not None:
            src_ip = datagram.getfieldval('src')
            dst_ip = datagram.getfieldval('dst')
            segment = i.payload
            src += ' ' + src_ip
            dst += ' ' + dst_ip
            if segment is not None:
                src_port = segment.getfieldval('sport')
                dst_port = segment.getfieldval('dport')
                src += ' {}'.format(src_port)
                dst += ' {}'.format(dst_port)
        stream = {src, dst}
        if stream not in streams:
            streams.append(stream)

    return streams


def find_udp_streams(packets: PacketList):
    streams = []
    for i in packets:
        if i.haslayer('UDP') == 0:
            continue
        src_mac = i.getfieldval('src')
        dst_mac = i.getfieldval('dst')
        src = src_mac
        dst = dst_mac
        datagram = i.payload
        if datagram is not None:
            src_ip = datagram.getfieldval('src')
            dst_ip = datagram.getfieldval('dst')
            segment = i.payload
            src += ' ' + src_ip
            dst += ' ' + dst_ip
            if segment is not None:
                src_port = segment.getfieldval('sport')
                dst_port = segment.getfieldval('dport')
                src += ' {}'.format(src_port)
                dst += ' {}'.format(dst_port)
        stream = {src, dst}
        if stream not in streams:
            streams.append(stream)

    return streams


def find_ip_streams(packets: PacketList):
    streams = []
    for i in packets:
        if i.haslayer('IP') == 0:
            continue
        src_mac = i.getfieldval('src')
        dst_mac = i.getfieldval('dst')
        src = src_mac
        dst = dst_mac
        datagram = i.payload
        if datagram is not None:
            src_ip = datagram.getfieldval('src')
            dst_ip = datagram.getfieldval('dst')
            segment = i.payload
            src += ' ' + src_ip
            dst += ' ' + dst_ip

        stream = {src, dst}
        if stream not in streams:
            streams.append(stream)

    return streams


def find_dns_streams(packets: PacketList):
    streams = []
    for i in packets:
        if i.haslayer('DNS') == 0:
            continue
        src_mac = i.getfieldval('src')
        dst_mac = i.getfieldval('dst')
        src = src_mac
        dst = dst_mac
        datagram = i.payload
        if datagram is not None:
            src_ip = datagram.getfieldval('src')
            dst_ip = datagram.getfieldval('dst')
            segment = i.payload
            src += ' ' + src_ip
            dst += ' ' + dst_ip
            if segment is not None:
                src_port = segment.getfieldval('sport')
                dst_port = segment.getfieldval('dport')
                src += ' {}'.format(src_port)
                dst += ' {}'.format(dst_port)
        stream = {src, dst}
        if stream not in streams:
            streams.append(stream)

    return streams


def find_http_streams(packets: PacketList):
    print('Http')
    streams = []
    for i in packets:
        if i.haslayer(http.HTTPRequest) == 0 and i.haslayer(http.HTTPResponse) == 0:
            continue
        src_mac = i.getfieldval('src')
        dst_mac = i.getfieldval('dst')
        src = src_mac
        dst = dst_mac
        datagram = i.payload
        if datagram is not None:
            src_ip = datagram.getfieldval('src')
            dst_ip = datagram.getfieldval('dst')
            segment = i.payload
            src += ' ' + src_ip
            dst += ' ' + dst_ip
            if segment is not None:
                src_port = segment.getfieldval('sport')
                dst_port = segment.getfieldval('dport')
                src += ' {}'.format(src_port)
                dst += ' {}'.format(dst_port)
        stream = {src, dst}
        if stream not in streams:
            streams.append(stream)

    return streams


def find_snmp_streams(packets: PacketList):
    streams = []
    for i in packets:

        src_mac = i.getfieldval('src')
        dst_mac = i.getfieldval('dst')
        src = src_mac
        dst = dst_mac
        datagram = i.payload
        if datagram is not None:
            src_ip = datagram.getfieldval('src')
            dst_ip = datagram.getfieldval('dst')
            segment = i.payload
            src += ' ' + src_ip
            dst += ' ' + dst_ip
            if segment is not None:
                src_port = segment.getfieldval('sport')
                dst_port = segment.getfieldval('dport')
                if (src_port != 161 and dst_port != 161) and (src_port != 162 and dst_port != 162):
                    break

                src += ' {}'.format(src_port)
                dst += ' {}'.format(dst_port)
        stream = {src, dst}
        if stream not in streams:
            streams.append(stream)

    return streams


def get_stream(stream, packets: PacketList):
    n = len(list(stream)[0].split(' '))  # 判断流属于哪一层 n=1 物理 n=2 网络 n=3 传输 n=4 应用

    stream_packets = []
    for i in packets:
        src_mac = i.getfieldval('src')
        dst_mac = i.getfieldval('dst')
        src = src_mac
        dst = dst_mac
        datagram = i.payload
        if datagram is not None and n > 1:
            src_ip = datagram.getfieldval('src')
            dst_ip = datagram.getfieldval('dst')
            segment = i.payload
            src += ' ' + src_ip
            dst += ' ' + dst_ip
            if segment is not None and n > 2:
                src_port = segment.getfieldval('sport')
                dst_port = segment.getfieldval('dport')
                src += ' {}'.format(src_port)
                dst += ' {}'.format(dst_port)

        if src in stream and dst in stream:
            stream_packets.append(i)

    return stream_packets


def get_tcp_pair(dst_pack: Packet, packets: PacketList):
    seq = dst_pack['TCP'].getfieldval('seq')
    stream = find_tcp_streams(dst_pack)[0]

    res = get_stream(stream, packets)
    n = len(list(stream)[0].split(' '))  # 判断流属于哪一层 n=1 物理 n=2 网络 n=3 传输 n=4 应用
    ack = 0
    stream_packets = []
    for i in packets:
        src_mac = i.getfieldval('src')
        dst_mac = i.getfieldval('dst')
        src = src_mac
        dst = dst_mac
        datagram = i.payload
        if datagram is not None and n > 1:
            src_ip = datagram.getfieldval('src')
            dst_ip = datagram.getfieldval('dst')
            segment = i.payload
            src += ' ' + src_ip
            dst += ' ' + dst_ip
            if segment is not None and n > 2:
                src_port = segment.getfieldval('sport')
                dst_port = segment.getfieldval('dport')
                ack = segment.getfieldval('ack')
                src += ' {}'.format(src_port)
                dst += ' {}'.format(dst_port)

        if src in stream and dst in stream and ack == seq + 1:
            return i


def get_RTT(pack: Packet, packets: PacketList):
    pair = get_tcp_pair(pack, packets)
    if pair is None:
        return False
    else:
        return pair.time - pack.time


def get_tcp_seq_list(packets: PacketList):
    seq_list1 = []
    seq_list2 = []
    current_list = seq_list1
    current_sport = None
    current_dport = None
    for pack in packets:
        tcp_datagram = pack['TCP']
        if tcp_datagram:
            dport = tcp_datagram.getfieldval('dport')
            sport = tcp_datagram.getfieldval('sport')

            if dport != current_dport and sport != current_sport:

                current_sport = sport
                current_dport = dport
                current_list = seq_list2 if current_list == seq_list1 else seq_list1
            else:

                current_dport = dport
                current_sport = sport

            current_list.append(tcp_datagram.getfieldval('seq'))
    current_list.append((current_sport, current_dport))
    current_list = seq_list2 if current_list == seq_list1 else seq_list1
    current_list.append((current_dport, current_sport))
    return seq_list1, seq_list2


def get_tcp_init_num(packets: PacketList):
    dport = None
    sport = None
    client_init = None
    server_init = None
    for pack in packets:
        tcp_datagram = pack['TCP']
        if tcp_datagram:
            dport = tcp_datagram.getfieldval('dport')
            sport = tcp_datagram.getfieldval('sport')
            if tcp_datagram.getfieldval('flags') == 'SA':
                client_init = tcp_datagram.getfieldval('ack') - 1
                server_init = tcp_datagram.getfieldval('seq')
                break

    return [[client_init, (dport, sport)], [server_init, (sport, dport)]]


def get_tcp_len_list(packets: PacketList):
    current_sport = None
    current_dport = None
    first_time = None
    length_list1 = []
    length_list2 = []
    current_list = None
    for pack in packets:
        tcp_datagram = pack['TCP']
        if tcp_datagram:
            dport = tcp_datagram.getfieldval('dport')
            sport = tcp_datagram.getfieldval('sport')
            if first_time is None:
                first_time = pack.time

            if dport != current_dport and sport != current_sport:
                current_sport = sport
                current_dport = dport
                current_list = length_list1 if current_list != length_list1 else length_list2
                time = pack.time - first_time

                length = len(tcp_datagram.payload)
                current_list.append([time, length])

            else:
                time = pack.time - first_time
                length = len(tcp_datagram.payload)
                current_list.append([time, length])

    current_list.append((current_sport, current_dport))
    current_list = length_list1 if current_list != length_list1 else length_list2
    current_list.append((current_dport, current_sport))
    return length_list1, length_list2


def get_tcp_throughput(packets: PacketList):
    res = get_tcp_len_list(packets)
    stream1 = res[0]

    datasize1 = 0
    throughput1 = []
    (sport, dport) = stream1.pop()
    for i in stream1:
        time = i[0]
        datasize1 += i[1]

        throughput = datasize1 / time if time != 0 else 0
        throughput1.append([time, throughput])
    throughput1.append((sport, dport))
    stream2 = res[1]

    datasize2 = 0
    throughput2 = []
    (sport, dport) = stream2.pop()
    for i in stream1:
        time = i[0]
        datasize2 += i[1]

        throughput = datasize2 / time if time != 0 else 0
        throughput2.append([time, throughput])
    throughput2.append((sport, dport))
    return throughput1, throughput2


def get_tcp_win_list(packets: PacketList):
    current_sport = None
    current_dport = None
    first_time = None
    win_list1 = []
    win_list2 = []
    current_list = None
    for pack in packets:
        tcp_datagram = pack['TCP']
        if tcp_datagram:
            dport = tcp_datagram.getfieldval('dport')
            sport = tcp_datagram.getfieldval('sport')
            win = tcp_datagram.window
            if first_time is None:
                first_time = pack.time
            if dport != current_dport and sport != current_sport:
                current_sport = sport
                current_dport = dport
                current_list = win_list1 if current_list != win_list1 else win_list2

            current_list.append([pack.time - first_time, win])

    current_list.append((current_sport, current_dport))
    current_list = win_list1 if current_list != win_list1 else win_list2
    current_list.append((current_dport, current_sport))
    return win_list1, win_list2


DNS_OPCODES = {0: 'Query', 1: 'IQuery', 2: 'Staus', 4: 'Notify', 5: 'Update'}
DNS_CLASSES = {1: "IN", 2: "CS", 3: "CH", 4: "HS"}
DNS_RCODES = {
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
    6: "YXDomain",
    7: "YXRRSet",
    8: "NXRRSet",
    9: "NotAuth",
    10: "NotZone",
    11: "Reserved"
}
DNS_QTYPES = {
    1: "A",
    2: "NS",
    3: "MD",
    4: "MF",
    5: "CNAME",
    6: "SOA",
    7: "MB",
    8: "MG",
    9: "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    252: "AXFR",
    255: "ANY"  # 255对应的特殊查询类型
}


def get_dns_graph(packets: PacketList):
    query_num = 0
    response_num = 0
    opcodes = {}
    query_types = {}
    classes = {}
    rcodes = {}

    for pack in packets:

        dns = pack['DNS']
        print(len(dns))
        print(len(dns.payload))
        if dns.qr == 1:
            response_num += 1
        else:
            query_num += 1

        opcode = DNS_OPCODES[dns.opcode] if dns.opcode in DNS_OPCODES.keys() else 'Unassigned'
        rcode = DNS_RCODES[dns.rcode] if dns.rcode in DNS_RCODES.keys() else 'Unassigned'
        if opcode in opcodes.keys():
            opcodes[opcode] += 1
        else:
            opcodes[opcode] = 1
        if rcode in rcodes.keys():
            rcodes[rcode] += 1
        else:
            rcodes[rcode] = 1
        query = dns.qd
        while query and dns.qr:
            query_type = DNS_QTYPES[query.qtype]
            query_class = DNS_CLASSES[query.qclass]
            if query_type in query_types.keys():
                query_types[query_type] += 1
            else:
                query_types[query_type] = 1
            if query_class in classes.keys():
                classes[query_class] += 1
            else:
                classes[query_class] = 1
            query = query.payload
        answer = dns.an
        while answer and dns.qr:

            answer_type = DNS_QTYPES[answer.type]
            answer_class = DNS_CLASSES[answer.rclass]
            if answer_type in query_types.keys():
                query_types[answer_type] += 1
            else:
                query_types[answer_type] = 1
            if answer_class in classes.keys():
                classes[answer_class] += 1
            else:
                classes[answer_class] = 1
            answer = answer.payload
        nameserver = dns.ns
        while nameserver:
            ns_class = DNS_CLASSES[nameserver.rclass]
            if ns_class in classes.keys():
                classes[ns_class] += 1
            else:
                classes[ns_class] = 1
            nameserver = nameserver.payload
        ar = dns.ar
        while ar:
            ar_class = DNS_CLASSES[ar.rclass]
            if ar_class in classes.keys():
                classes[ar_class] += 1
            else:
                classes[ar_class] = 1
            ar = ar.payload

    return opcodes, rcodes, query_types, classes, {'QueryNum': query_num, 'ResponseNum': response_num}


def get_dns_len_list(packets:PacketList):
    len_list = []
    for pack in packets:
        dns = pack['DNS']
        len_list.append(len(dns))
    return len_list


def get_dns_pair(pack:Packet, packets:PacketList):
    dns_id = pack["DNS"].id
    for i in packets:
        if i!=pack:
            if dns_id == pack['DNS'].id:
                return i

    return None


if __name__ == '__main__':
    load_layer('http')
    s = Sniffer()
    s.sniff_start(count=30, offline='3.pcap')
    res = s.sniff_result()

    s = find_dns_streams(res)
    res = get_stream(s[0], res)

    for i in res:
        get_dns_pair(i,res).show()
