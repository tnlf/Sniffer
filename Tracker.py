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
                if (src_port != 161 and dst_port !=161) and (src_port !=162 and dst_port != 162) :
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

def get_pair(dst_pack: Packet , packets: PacketList):
    seq = dst_pack['TCP'].getfieldval('seq')
    stream = find_tcp_streams(dst_pack)[0]

    res = get_stream(stream, packets)
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
                ack = segment.getfieldval('ack')
                src += ' {}'.format(src_port)
                dst += ' {}'.format(dst_port)

        if src in stream and dst in stream and ack == seq+1:
            return i

def get_RTT(pack: Packet, packets: PacketList):
    pair = get_pair(pack, packets)
    if pair is None:
        return False
    else:
        return pair.time- pack.time

if __name__ == '__main__':
    load_layer('http')
    s = Sniffer()
    s.sniff_start(count=10)
    res = s.sniff_result()

    s = find_tcp_streams(res)
    res = get_stream(s[0], res)

    for i in res:
        #i['TCP'].show()
        print(get_RTT(i, res))
