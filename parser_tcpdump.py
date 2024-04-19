
import re
def parse_packet(line):
    # Expresión regular para hacer coincidir los elementos de la línea
    patternS = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sseq\s(\d+(?::\d+)?),\sack\s(\d+),\swin\s(\d+),\soptions\s\[(.*?)\],\slength\s(\d+)'
    patternNoSeq = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sack\s(\d+),\swin\s(\d+),\soptions\s\[(.*?)\],\slength\s(\d+)'
    patternNoSeqNoOpt = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sack\s(\d+),\swin\s(\d+),\slength\s(\d+)'
    patternNoAck = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sseq\s(\d+),\swin\s(\d+),\soptions\s\[(.*?)\],\slength\s(\d+)'
    patternNoAckNoOpt = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sseq\s(\d+(?::\d+)?),\swin\s(\d+),\slength\s(\d+)'
    patternNoOpt = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sseq\s(\d+(?::\d+)?),\sack\s(\d+),\swin\s(\d+),\slength\s(\d+)'
    patternUdp = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sUDP,\slength\s(\d+)'
    patternDns = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\s(\d+)\+\s([A-Z])\?\s([\w\.-]+)\.\s\((\d+)\)'
    #patternIcmp = r'(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([\d.]+)\s*>\s*([\d.]+):\s+ICMP\s+(\d+\.\d+\.\d+\.\d+)\s+tcp\s+port\s+(\d+)\s+unreachable,\s+length\s+(\d+)'

    algun_match = False
    match = re.match(patternS, line)
    match3 = re.match(patternNoSeq, line)
    match4 = re.match(patternNoSeqNoOpt, line)
    match5 = re.match(patternNoAck, line)
    match6 = re.match(patternNoAckNoOpt, line)
    match7 = re.match(patternNoOpt, line)
    match8 = re.match(patternUdp, line)
    match9 = re.match(patternDns, line)
    if match:
        timestamp = match.group(1)
        src_ip = match.group(2)
        src_port = match.group(3)
        dst_ip = match.group(4)
        dst_port = match.group(5)
        flags = match.group(6)
        seq = match.group(7)
        ack = match.group(8)
        win = match.group(9)
        options = match.group(10)
        len = match.group(11)
        type = "TCP"
        algun_match = True
    else :
        if match3:
            timestamp = match3.group(1)
            src_ip = match3.group(2)
            src_port = match3.group(3)
            dst_ip = match3.group(4)
            dst_port = match3.group(5)
            flags = match3.group(6)
            seq = ""
            ack = match3.group(7)
            win = match3.group(8)
            options = match3.group(9)
            len = match3.group(10)
            type = "TCP"
            algun_match = True
        else:
            if match4:
                timestamp = match4.group(1)
                src_ip = match4.group(2)
                src_port = match4.group(3)
                dst_ip = match4.group(4)
                dst_port = match4.group(5)
                flags = match4.group(6)
                seq = ""
                ack = match4.group(7)
                win = match4.group(8)
                options = ""
                len = match4.group(9)
                type = "TCP"
                algun_match = True
            else:
                if match5: 
                    timestamp = match5.group(1)
                    src_ip = match5.group(2)
                    src_port = match5.group(3)
                    dst_ip = match5.group(4)
                    dst_port = match5.group(5)
                    flags = match5.group(6)
                    seq = match5.group(7)
                    ack = ""
                    win = match5.group(8)
                    options = match5.group(9)
                    len = match5.group(10)
                    type = "TCP"
                    algun_match = True
                else:
                    if match6:
                        timestamp = match6.group(1)
                        src_ip = match6.group(2)
                        src_port = match6.group(3)
                        dst_ip = match6.group(4)
                        dst_port = match6.group(5)
                        flags = match6.group(6)
                        seq = match6.group(7)
                        ack = ""
                        win = match6.group(8)
                        options = ""
                        len = match6.group(9)
                        type = "TCP"
                        algun_match = True
                    else:
                        if match7:
                            timestamp = match7.group(1)
                            src_ip = match7.group(2)
                            src_port = match7.group(3)
                            dst_ip = match7.group(4)
                            dst_port = match7.group(5)
                            flags = match7.group(6)
                            seq = match7.group(7)
                            ack = match7.group(8)
                            win = match7.group(9)
                            options = ""
                            len = match7.group(10)
                            type = "TCP"
                            algun_match = True
                        else:
                            if match8: 
                                timestamp = match8.group(1)
                                src_ip = match8.group(2)
                                src_port = match8.group(3)
                                dst_ip = match8.group(4)
                                dst_port = match8.group(5)
                                flags = ""
                                seq = ""
                                ack = ""
                                win = ""
                                options = "UDP"
                                len = match8.group(6)
                                type = "UDP"
                                algun_match = True
                            else:
                                if match9:
                                    timestamp = match9.group(1)
                                    src_ip = match9.group(2)
                                    src_port = match9.group(3)
                                    dst_ip = match9.group(4)
                                    dst_port = match9.group(5)
                                    flags = match9.group(6)+match9.group(7)
                                    seq = ""
                                    ack = ""
                                    win = ""
                                    options = match9.group(8)
                                    len = match9.group(9)
                                    type = "DNS"
                                    algun_match = True

    if algun_match:       
        return {
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flags": flags,
                    "seq": seq,
                    "ack": ack,
                    "win": win,
                    "options": options,
                    "len": len,
                    "type": type
                }
    else:
        print("---------------------------------No match--------------------------------")
        return None