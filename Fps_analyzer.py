#coding:utf-8

from scapy.all import *
import datetime

class PacketError(Exception): pass
class PacketTypeError(PacketError): pass

class Fps_data:
    def __init__(self, start_time, end_time, pkt_count):
        self.start_time = start_time
        self.end_time = end_time
        self.pkt_count = pkt_count

    def format_fps_data(self):
        dt = datetime.datetime.fromtimestamp(self.start_time)
        start_time = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
        dt = datetime.datetime.fromtimestamp(self.end_time)
        end_time = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
        return "From {0} To {1}, fps={2}".format(start_time, end_time, self.pkt_count)

class Fps_analyzer:
    def __init__(self, filePath = None):
        self.filePath = filePath
        self.fps_results = defaultdict(list)
        self.fps_nodes = {}

    def parse_pcap_packet(self, pcap_packet):
        if "IP" not in pcap_packet:
            raise PacketTypeError("Missing IP layer")

        if "UDP" not in pcap_packet:
            if "ICMP" in pcap_packet:
                return (None, None)
            raise PacketTypeError("Missing UDP layer")

        if "Raw" not in pcap_packet:
            raise PacketTypeError("Missing media data")

        if  pcap_packet["UDP"].len <= 12:
            return (None, None)

        network = pcap_packet["IP"].src, pcap_packet["UDP"].sport, pcap_packet["IP"].dst, pcap_packet["UDP"].dport
        try:
            rtpInfo = RTP(pcap_packet["Raw"].load)
            frame_marker = 0
            if rtpInfo.marker:
                frame_marker = 1
            packet = pcap_packet.time, frame_marker
            return network,packet
        except (Exception) as err:
            raise PacketTypeError("invalid data for rtp")

    def process_fps_from_file(self, filename = None):
        if filename is not None:
            self.filePath = filename

        self.fps_results.clear()
        self.fps_nodes.clear()

        pkt_handle = None
        try:
            pkt_handle = PcapReader(self.filePath)
            while True:
                pkt_data = pkt_handle.read_packet()
                if pkt_data is None:
                    for key, fps in self.fps_nodes.items():
                        self.fps_results[key].append(fps)
                    break
                key, value = self.parse_pcap_packet(pkt_data)
                if key is None or value is None:
                    continue

                fps_data = self.fps_nodes.get(key)
                if fps_data is None:
                    fps_data = Fps_data(value[0], value[0], value[1])
                    self.fps_nodes[key] = fps_data
                else:
                    if value[0] - fps_data.start_time >= 1:
                        self.fps_results[key].append(fps_data)
                        self.fps_nodes.pop(key)
                        fps_data = Fps_data(value[0], value[0], value[1])
                        self.fps_nodes[key] = fps_data
                    else:
                        fps_data.end_time = value[0]
                        fps_data.pkt_count += value[1]
        except (PacketError) as err:
            print("parse packets faild:{0}".format(err))
            return
        finally:
            if pkt_handle is not None:
                pkt_handle.close()

    def format_fps(self):
        for net, fps in self.fps_results.items():
            output = ""
            net = "src:{0} sport:{1} dst:{2} dport:{3}\n".format(net[0], net[1], net[2], net[3])
            output += net
            if fps is not None:
                for i_fps in fps:
                    fps_data = "{0}\n".format(i_fps.format_fps_data())
                    output += fps_data
        return output
