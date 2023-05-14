package main

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Packet struct {
	time       time.Time
	truncated  bool
	protocol   string
	sourceIP   net.IP
	destIP     net.IP
	sourcePort layers.TCPPort
	destPort   layers.TCPPort
	packetSize int
	dump       []string
}

// String returns a string representation of the Packet
func (p Packet) String() string {
	return fmt.Sprintf(
		"Packet\tTime: %v\tTruncated: %v\n"+
			"\tProtocol: %s\tSourceIP: %v\tDestIP: %v\n"+
			"\tSourcePort: %d\tDestPort: %d\tPacketSize: %d\n"+
			"Dump: \n%v\n",
		p.time, p.truncated,
		p.protocol, p.sourceIP, p.destIP,
		p.sourcePort, p.destPort, p.packetSize,
		p.dump,
	)
}

func createHandle(Name string, promisc bool) *pcap.Handle {
	if promisc {
		handle, err := pcap.OpenLive(Name, 65535, true, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
		return handle
	} else {
		handle, err := pcap.OpenLive(Name, 65535, false, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
		return handle
	}
}

var file os.File // file for writing packet data

// Sniff captures and displays network traffic in a GUI table
func Sniff(table *widgets.QTableWidget, settings *Settings) {
	if settings.save {
		file, err := os.Create(time.Now().Format("2006_01_02_15_04_05") + ".txt")
		defer file.Close()
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	timer := time.After(time.Duration(settings.time) * time.Millisecond)

	// Find all available network interfaces
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Print the details of each network interface
	for _, iface := range ifs {
		fmt.Println("Interface Name:", iface.Name)
		fmt.Println("Interface Addresses:", iface.Addresses)
		fmt.Println("Interface Flags:", iface.Flags)
	}

	var wg sync.WaitGroup
	for _, iface := range ifs {
		wg.Add(1)
		var num = 0

		// Start a separate goroutine to capture packets on each interface
		go func(iface pcap.Interface) {
			defer wg.Done()

			// Open a handle to the network interface for packet capture
			handle := createHandle(iface.Name, settings.promisc)
			defer handle.Close()

			// Set a packet capture filter, if specified
			if settings.protocols != "all" && settings.protocols != "" {
				filter := settings.protocols
				err = handle.SetBPFFilter(filter)
				if err != nil {
					log.Fatal(err)
				}
			}

			// Start capturing packets and processing them
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packetS := range packetSource.Packets() {
				fmt.Println("in")
				if settings.time != 0 {
					fmt.Println("in2")
					go func() {
						if <-timer == time.Now() {
							fmt.Println("time is over!!")
							os.Exit(0)
						}
					}()

				}
				num += 1

				// Create a new packet instance
				packet := new(Packet)

				// Set the packet number, packet size, and timestamp from packetS.Metadata()
				packet.packetSize = packetS.Metadata().CaptureLength
				packet.time = packetS.Metadata().Timestamp

				// Determine the protocol of the packet by checking the last layer
				// If there is only one layer, use that layer's type as the protocol
				packetLayer := packetS.Layers()
				if len(packetLayer) > 1 {
					i := len(packetLayer) - 2
					packet.protocol = packetLayer[i].LayerType().String()
				} else {
					packet.protocol = packetLayer[0].LayerType().String()
				}

				// If the packet has an IPv4 layer, set the source and destination IP addresses
				if packetS.Layer(layers.LayerTypeIPv4) != nil {
					ipLayer := packetS.Layer(layers.LayerTypeIPv4)
					if ipLayer.(*layers.IPv4) != nil {
						ip := ipLayer.(*layers.IPv4)
						packet.sourceIP = ip.SrcIP
						packet.destIP = ip.DstIP
					} else if ipLayer.(*layers.IPv6) != nil {
						ip := ipLayer.(*layers.IPv6)
						packet.sourceIP = ip.SrcIP
						packet.destIP = ip.DstIP
					}
				}

				// If the packet has a TCP layer, set the source and destination port numbers
				if tcpLayer := packetS.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					packet.sourcePort = tcp.SrcPort
					packet.destPort = tcp.DstPort
				}

				// Append the hex dump of the packet to packet.dump
				packet.dump = append(packet.dump, hex.Dump(packetS.Data()))

				// Set the value of packet.truncated to the truncated field of packetS.Metadata()
				packet.truncated = packetS.Metadata().Truncated

				// Write the packet to file if settings.save is true
				if settings.save {
					file.WriteString(packet.String())
				}

				// Insert a new row into the table and set the QTableWidgetItem values for each field
				rowC := table.RowCount()
				table.InsertRow(rowC)

				// Set the remaining QTableWidgetItem values
				timeStr := packet.time.Format("15:04:05 02-01-2006 ")
				table.SetItem(rowC, 0, widgets.NewQTableWidgetItem2(timeStr, 0))
				table.SetItem(rowC, 1, widgets.NewQTableWidgetItem2(packet.protocol, 1))
				table.SetItem(rowC, 2, widgets.NewQTableWidgetItem2(strconv.Itoa(packet.packetSize), 2))
				table.SetItem(rowC, 3, widgets.NewQTableWidgetItem2(packet.sourceIP.String(), 3))
				table.SetItem(rowC, 4, widgets.NewQTableWidgetItem2(packet.destIP.String(), 4))
				table.SetItem(rowC, 5, widgets.NewQTableWidgetItem2(packet.sourcePort.String(), 5))
				table.SetItem(rowC, 6, widgets.NewQTableWidgetItem2(packet.destPort.String(), 6))
				table.SetItem(rowC, 7, widgets.NewQTableWidgetItem2(strconv.FormatBool(packet.truncated), 7))
				table.SetItem(rowC, 8, widgets.NewQTableWidgetItem2(strings.Join(packet.dump, "\n"), 8))

				// Set the background color of the protocol field in the table
				color := gui.NewQBrush3(gui.NewQColor2(core.Qt__white), core.Qt__BrushStyle(1))
				switch packet.protocol {
				case "TCP":
					color = gui.NewQBrush3(gui.NewQColor2(core.Qt__darkRed), core.Qt__BrushStyle(1))
				case "UDP":
					color = gui.NewQBrush3(gui.NewQColor2(core.Qt__cyan), core.Qt__BrushStyle(1))
				case "SCTP":
					color = gui.NewQBrush3(gui.NewQColor2(core.Qt__darkMagenta), core.Qt__BrushStyle(1))
				case "IPv4":
					color = gui.NewQBrush3(gui.NewQColor2(core.Qt__magenta), core.Qt__BrushStyle(1))
				case "IPv6":
					color = gui.NewQBrush3(gui.NewQColor2(core.Qt__darkGreen), core.Qt__BrushStyle(1))
				}
				table.Item(rowC, 1).SetBackground(color)
			}

		}(iface)

	}

	wg.Wait()
}
