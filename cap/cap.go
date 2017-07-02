package main

import (
    // "github.com/google/gopacket"
    // "github.com/google/gopacket/pcap"
    // "github.com/google/gopacket/layers"
    // "math/big"
    // "github.com/inject/anguslang/inject"

    "fmt"
    "bytes"
    "encoding/binary"
)

// var (
//     handle      *pcap.Handle
//     options     gopacket.SerializeOptions
// )

func ComputeTCPChecksum(buf []byte, l int) (uint16) {
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

// func handlePacket(packet gopacket.Packet) {
//
// }


func testCheckSum() {

    var outgoing_packet bytes.Buffer

    l, _ := outgoing_packet.WriteString("asdasdasdasdasdasdasdasdadsadaasdasdasdasdasdasdasdjahsld;kjalksjdlajsldjlajdlajsdljaslkasdaasdasdasdasdasdnasdnasmnd,amns,dn,asnd,mnasmnd,asn,dssasdasdasdasdasdasdasdasdadsadaasdasdasdasdasdasdasdjahsld;kjalksjdlajsldjlajdlajsdljaslkasdaasdasdasdasdasdnasdnasmnd,amns,dn,asnd,mnasmnd,asn,dss")

    fmt.Println(l)
    fmt.Printf("%x\n", l >> 8)
    fmt.Printf("%x\n", l & 0xff)
}

func main() {


    testCheckSum()
    // var devices []pcap.Interface
    // devices, _ = pcap.FindAllDevs()
    //
    // fmt.Println(devices)

    // handle, _ = pcap.OpenLive(
    //     "en0",
    //     1600,
    //     true,
    //     pcap.BlockForever,
    // )
    //
    // handle.SetBPFFilter("tcp and port 80")
    //
    // packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    //
    // for packet := range packetSource.Packets() {
    //     go handlePacket(packet)
    // }
    //
    // defer handle.Close()

}
