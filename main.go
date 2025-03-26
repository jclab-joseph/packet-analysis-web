//go:build js
// +build js

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gopacket/gopacket/pcapgo"
	"syscall/js"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type PacketDataSource interface {
	gopacket.PacketDataSource
	LinkType() layers.LinkType
}

type Packet struct {
	ID        int    `json:"id"`
	Timestamp string `json:"timestamp"`
	Protocol  string `json:"protocol"`
	Length    int    `json:"length"`
	SrcIP     string `json:"srcIp,omitempty"`
	DstIP     string `json:"dstIp,omitempty"`
	SrcPort   uint16 `json:"srcPort,omitempty"`
	DstPort   uint16 `json:"dstPort,omitempty"`
	Hash      string `json:"hash"`
	Info      string `json:"info"`
}

type DuplicatedPacket struct {
	Hash   string `json:"hash"`
	CountA int    `json:"countA"`
	CountB int    `json:"countB"`
	Info   string `json:"info"`
}

type AnalysisResult struct {
	Dropped    []Packet           `json:"dropped"`
	Inserted   []Packet           `json:"inserted"`
	Duplicated []DuplicatedPacket `json:"duplicated"`
	CountA     int                `json:"countA"`
	CountB     int                `json:"countB"`
}

func main() {
	c := make(chan struct{}, 0)
	js.Global().Set("analyzePcapFiles", js.FuncOf(analyzePcapFiles))
	<-c
}

func analyzePcapFiles(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return js.ValueOf("두 개의 PCAP 파일이 필요합니다.")
	}

	// JavaScript Uint8Array를 Go 슬라이스로 변환
	fileABytes := make([]byte, args[0].Length())
	fileBBytes := make([]byte, args[1].Length())

	js.CopyBytesToGo(fileABytes, args[0])
	js.CopyBytesToGo(fileBBytes, args[1])

	// PCAP 파일 파싱
	packetsA, err := parsePcapWithGoPacket(fileABytes)
	if err != nil {
		return js.ValueOf(fmt.Sprintf("첫 번째 PCAP 파일 파싱 오류: %v", err))
	}

	packetsB, err := parsePcapWithGoPacket(fileBBytes)
	if err != nil {
		return js.ValueOf(fmt.Sprintf("두 번째 PCAP 파일 파싱 오류: %v", err))
	}

	// 패킷 비교 분석
	result := analyzePcaps(packetsA, packetsB)

	// JSON으로 변환
	jsonResult, err := json.Marshal(result)
	if err != nil {
		return js.ValueOf(fmt.Sprintf("결과 직렬화 오류: %v", err))
	}

	return js.ValueOf(string(jsonResult))
}

func parsePcapWithGoPacket(data []byte) ([]Packet, error) {
	// PCAPng 파일인지 확인하고 적절한 방식으로 처리
	var handle PacketDataSource
	var err error

	handle, err = pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		handle, err = pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.NgReaderOptions{
			SkipUnknownVersion: true,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("PCAP 파일을 열 수 없습니다: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var packets []Packet
	packetID := 1

	// 모든 패킷 처리
	for packet := range packetSource.Packets() {
		// 패킷 기본 정보 추출
		captureInfo := packet.Metadata().CaptureInfo
		timestamp := captureInfo.Timestamp.Format("2006-01-02 15:04:05.000000")
		length := captureInfo.Length

		// 프로토콜 분석
		protocol := "Unknown"
		srcIP := ""
		dstIP := ""
		info := ""
		var srcPort, dstPort uint16

		// 네트워크 계층 처리 (IP)
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			protocol = ip.Protocol.String()
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()

			info = "ip.src == " + srcIP + " && ip.dst == " + dstIP
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			protocol = ip.NextHeader.String()
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		}

		// 전송 계층 처리 (TCP, UDP)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			protocol = "TCP"
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
			info = info + fmt.Sprintf("&& tcp.srcport == %d && tcp.dstport == %d && tcp.seq_raw == %d && tcp.ack_raw == %d", srcPort, dstPort, tcp.Seq, tcp.Ack)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			protocol = "UDP"
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
		} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			protocol = "ICMP"
		} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
			protocol = "ICMPv6"
		} else if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			protocol = "ARP"
		}

		// 애플리케이션 계층 확인 (가능한 경우)
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			// 잘 알려진 포트 확인
			if srcPort == 80 || dstPort == 80 {
				protocol = "HTTP"
			} else if srcPort == 443 || dstPort == 443 {
				protocol = "HTTPS"
			} else if srcPort == 53 || dstPort == 53 {
				protocol = "DNS"
			}
		}

		var hash [32]byte
		if info == "" {
			// 패킷 바이너리 데이터 해시 계산
			packetData := packet.Data()
			hash = sha256.Sum256(packetData)
		} else {
			hash = sha256.Sum256([]byte(info))
		}
		hashStr := hex.EncodeToString(hash[:])

		// 패킷 객체 생성
		p := Packet{
			ID:        packetID,
			Timestamp: timestamp,
			Protocol:  protocol,
			Length:    length,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Hash:      hashStr,
			Info:      info,
		}

		packets = append(packets, p)
		packetID++
	}

	return packets, nil
}

func analyzePcaps(packetsA, packetsB []Packet) AnalysisResult {
	result := AnalysisResult{
		CountA:     len(packetsA),
		CountB:     len(packetsB),
		Dropped:    []Packet{},
		Inserted:   []Packet{},
		Duplicated: []DuplicatedPacket{},
	}

	// 패킷 해시 맵 생성
	hashMapA := make(map[string][]Packet)
	hashMapB := make(map[string][]Packet)

	for _, packet := range packetsA {
		hashMapA[packet.Hash] = append(hashMapA[packet.Hash], packet)
	}

	for _, packet := range packetsB {
		hashMapB[packet.Hash] = append(hashMapB[packet.Hash], packet)
	}

	// 1. A에만 있는 패킷 (dropped)
	for hash, packets := range hashMapA {
		if _, exists := hashMapB[hash]; !exists {
			result.Dropped = append(result.Dropped, packets...)
		}
	}

	// 2. B에만 있는 패킷 (inserted)
	for hash, packets := range hashMapB {
		if _, exists := hashMapA[hash]; !exists {
			result.Inserted = append(result.Inserted, packets...)
		}
	}

	// 3. 중복된 패킷
	for hash, countA := range hashMapA {
		countB, exists := hashMapB[hash]
		if exists && len(countA) != len(countB) {
			result.Duplicated = append(result.Duplicated, DuplicatedPacket{
				Hash:   hash,
				CountA: len(countA),
				CountB: len(countB),
				Info:   countA[0].Info,
			})
		}
	}

	return result
}
