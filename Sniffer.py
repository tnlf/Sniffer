from scapy.all import *


class Sniffer:
    def __init__(self):
        self.sniffer = None
        self.pks = []
        return

    def sniff_start(self, count=0, bpf_filter=None, offline=None, timeout=None, iface=None):
        self.sniffer = AsyncSniffer(count=count, filter=bpf_filter, offline=offline, timeout=timeout, iface=iface)
        self.sniffer.start()

    def sniff_stop(self):
        if (self.sniffer is not None) and self.sniffer.running:
            self.sniffer.stop()


    def sniff_result(self):
        self.sniffer.join()
        while self.sniffer.running:
            # print("1")
            pass

        self.pks = self.sniffer.results
        return self.pks


def show_packet(pack: packet.Packet):
    layer = pack

    layers = []
    while layer:
        print(layer.name)
        print("___________")
        fields = layer.fields
        for key in fields:

            print(key, fields[key])

        print("___________")
        layer = layer.payload



if __name__ == '__main__':
    s = Sniffer()
    s.sniff_start(count=1)
    res = s.sniff_result()
    for i in res:
        show_packet(i)