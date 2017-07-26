package main

import (
    // "github.com/anguslang/endian"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"

    "fmt"
    "bytes"
    // "encoding/binary"
)

var (
    handle *pcap.Handle
    pchan chan gopacket.Packet
    input int
)

func ExposeSelf(packet gopacket.Packet) {

    origin := packet.Data()

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

func main () {

    interfaces, _ := pcap.FindAllDevs()

    for i := 0; i < len(interfaces); i++ {
        fmt.Printf("[%d] %v\n", i, interfaces[i].Name)

        var int_addrs = interfaces[i].Addresses
        for j := 0; j < len(int_addrs); j++ {
            fmt.Printf("    %v\n",int_addrs[j].IP)
        }

    }
    fmt.Printf("which interface you will use to cap[0~%v]:", len(interfaces) - 1);
    fmt.Scanf("%d", &input)

    pchan = make(chan gopacket.Packet)

    handle, _ = pcap.OpenLive(
        interfaces[input].Name,
        1600,
        true,
        pcap.BlockForever,
    )

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    for packet := range packetSource.Packets() {
        go ExposeSelf(packet)
    }

    defer handle.Close()
}
