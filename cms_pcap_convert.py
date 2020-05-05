import csv
import sys

import cms_decode
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP

def process_file(in_file, out_file):
    with PcapReader(in_file) as pcap_reader, open(out_file, 'w') as csvfile:
        csv_writer = None
        state = {}
        for pkt in pcap_reader:
            if TCP in pkt and pkt[TCP].dport == 515:
                buf = pkt[TCP].load
                offset = 0
                state['time'] = pkt.time
                while offset < len(buf):
                    block = cms_decode.CmsDataBlock.ReadFromBytes(buf, offset)
                    if hasattr(block, 'values'):
                        state.update(block.values)
                    if hasattr(block, 'leads'):
                        state.update(block.leads)
                    if block.type == 0x47:
                        # write row
                        if not csv_writer:
                            fields = [k for k in sorted(state.keys()) if 'alarm' not in k]
                            csv_writer = csv.DictWriter(csvfile, fields, extrasaction='ignore')
                            csv_writer.writeheader()
                        csv_writer.writerow(state)
                    offset += 4 + block.length


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.stderr.write("Usage: cms_pcap_process <pcap_file> <csv_output_file>\n")
        sys.exit(-1)
    process_file(sys.argv[1], sys.argv[2])
