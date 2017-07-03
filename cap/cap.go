package main

import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    // "github.com/google/gopacket/layers"

    "fmt"
    "bytes"
    "strings"
    "encoding/binary"
)

var (
    handle *pcap.Handle
)

const LinkLayer_Len uint16 = 14

func computeIPChecksum(buf []byte) (uint16) {

	var cksum uint32 = 0
	for i:=0; i<20; i+=2 {
		cksum += uint32(binary.BigEndian.Uint16(buf[i+14:i+16]))
	}
	for ;cksum > 0xffff; {
		cksum = (cksum >> 16) + (cksum & 0xffff)
	}
	return ^uint16(cksum)
}

func computeTCPChecksum(buf []byte, l int) (uint16) {
	var cksum uint32 = 0
	l += 20
    //读伪头部
    for i:=0; i<8; i+=2 {
		cksum += uint32(binary.BigEndian.Uint16(buf[i+26:i+28]))
	}
    cksum += 0x06
    cksum += uint32(l)

    for i:=0; i<l; i+=2 {
		cksum += uint32(binary.BigEndian.Uint16(buf[i+34:i+36]))
	}
	for ;cksum > 0xffff; {
		cksum = (cksum >> 16) + (cksum & 0xffff)
	}
    return ^uint16(cksum)
}

func handlePacket(packet gopacket.Packet, url string) {

    origin := packet.Data()

    if (origin[33] == 0xe3){
        return
    }

    appLayer := packet.ApplicationLayer()

    if (appLayer == nil) {
        return
    }

    headers  := string( appLayer.Payload() )



    var buff bytes.Buffer

    // MAC Layer
    buff.Write(origin[6:12])
    buff.Write(origin[0: 6])
    buff.Write([]byte{0x08, 0x00})

    // IP Layer
    buff.Write([]byte{0x45, 0x00, 0x00, 0x00, 0x00, 0x00})
    buff.Write([]byte{0x40, 0x00, 0x40, 0x06})
    buff.Write([]byte{0x00, 0x00})

    buff.Write(origin[30:34])
    buff.Write(origin[26:30])

    local_endian := binary.BigEndian
    //
    // if ( endian.IsBigEndian() ) {
    //     local_endian = binary.BigEndian
    // } else {
    //     local_endian = binary.LittleEndian
    // }

    ip_header_len   := uint16( origin[14] & 0x0f * 4 )
    tcp_begin       := ip_header_len + LinkLayer_Len

    fmt.Println(tcp_begin)

    tcp_header_len  := uint16( origin[ip_header_len + 12] & 0xff )
    seq_num         := local_endian.Uint16(origin[tcp_begin + 4: tcp_begin + 8])
    total_len       := local_endian.Uint16(origin[16:18])

    buff.Write(origin[tcp_begin + 2: tcp_begin + 4])
    buff.Write(origin[tcp_begin    : tcp_begin + 2])

    buff.Write(origin[tcp_begin + 8: tcp_begin + 12])

    acknum := uint32(seq_num + total_len - ip_header_len - tcp_header_len)

    ackbytes := make([]byte, 4)
    local_endian.PutUint32(ackbytes, acknum)
    buff.Write(ackbytes)

    buff.Write([]byte{0x50, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

    //Application layer
    html := "HTTP/1.1 302 Found\r\nLocation: "+ url + "\r\n" +
    "Content-Length: 0\r\n" +
    "Cache-control: no-cache\r\n" +
    "Connection: close\r\n" +
    "Content-Type: text/html; charset=UTF-8\r\n\r\n"

    buff.WriteString(html)

    out := buff.Bytes()

    l               := len(html)
    check_sum_ip    := computeIPChecksum(out)
    check_sum_tcp   := computeTCPChecksum(out, l)

    if (local_endian == binary.BigEndian) {

        out[16] = byte(uint16(40 + l) >> 8);
        out[17] = byte(40 + l);

        out[24] = byte(check_sum_ip >> 8)
        out[25] = byte(check_sum_ip)

        out[tcp_begin + 16] = byte(check_sum_tcp >> 8)
        out[tcp_begin + 17] = byte(check_sum_tcp)

    } else {

        out[17] = byte(uint16(40+l) >> 8);
        out[16] = byte(40+l);

        out[25] = byte(check_sum_ip >> 8)
        out[24] = byte(check_sum_ip)

        out[tcp_begin + 17] = byte(check_sum_tcp >> 8)
        out[tcp_begin + 16] = byte(check_sum_tcp)

    }

    handle.WritePacketData(out)

    fmt.Println(out)

}

func main() {

    handle, _ = pcap.OpenLive(
        "en0",
        1600,
        true,
        pcap.BlockForever,
    )

    handle.SetBPFFilter("tcp and port 80")

    url := "http://wwww.pheicloud.com"

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    for packet := range packetSource.Packets() {

        go handlePacket(packet, url)

    }

    defer handle.Close()

}
