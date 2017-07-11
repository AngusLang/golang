package main

import (
    // "github.com/anguslang/endian"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"

    // "fmt"
    "bytes"
    // "encoding/binary"
)

var (
    handle *pcap.Handle
)

func ExposeSelf(packet gopacket.Packet) {

    origin := packet.Data()

    // fmt.Println(packet)

    if (origin[13] == 0x06 && origin[4] == 0xd6 && origin[5] === 0x29) {

        // fmt.Printf("arp request from %v\r\n", origin[28:32])

        var buff bytes.Buffer
        buff.Write(origin[6:12])
        buff.Write(origin[0:6])
        buff.Write([]byte{0x08, 0x06})

        // hardware type
        buff.Write([]byte{0x00, 0x01})
        // protocol type IPv4
        buff.Write([]byte{0x08, 0x00})
        // hardware size & protocol size
        buff.Write([]byte{0x06, 0x04})
        // operation code 00,01 request; 00, 02 reply
        buff.Write([]byte{0x00, 0x02})
        // sender Mac address
        buff.Write([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0x12})
        // sender Ip address
        buff.Write(origin[38:42])

        buff.Write(origin[22:32])

        out := buff.Bytes()

        handle.WritePacketData(out)

    }
}

func main () {
    handle, _ = pcap.OpenLive(
        "en0",
        1600,
        true,
        pcap.BlockForever,
    )

    // handle.SetBPFFilter("tcp and port 80")

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    for packet := range packetSource.Packets() {
        go ExposeSelf(packet)
    }

    defer handle.Close()
}
