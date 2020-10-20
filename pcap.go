package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile     string
	rawFile      string
	inputHandle  *pcap.Handle
	outputHandle *os.File
	err          error
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func openOutputFile(filename string) (*os.File, error) {
	var f *os.File
	var err error
	if checkFileIsExist(filename) { //如果文件存在
		fmt.Println("file exist , overwrite it")
		f, err = os.OpenFile(filename, os.O_APPEND, 0666) //打开文件
	} else {
		f, err = os.Create(filename) //创建文件
		fmt.Println("created output file")
	}
	return f, err
}

func checkMainArgs() {
	flag.StringVar(&pcapFile, "i", "", "inputFile.pcap")
	flag.StringVar(&rawFile, "o", "", "outputPayload.bin")
	flag.Parse()
	if pcapFile == "" || rawFile == "" {
		flag.Usage()
		os.Exit(1)
	}
	return
}

func main() {

	checkMainArgs()

	fmt.Printf("start time ：%v;\n", time.Now().Unix())

	// Open file instead of device
	inputHandle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer inputHandle.Close()

	outputHandle, err = openOutputFile(rawFile)
	if err != nil {
		log.Fatal(err)
	}
	defer outputHandle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(inputHandle, inputHandle.LinkType())
	for packet := range packetSource.Packets() {
		if app := packet.ApplicationLayer(); app != nil {
			_, err := outputHandle.Write(app.Payload())
			check(err)
		}
	}

	fmt.Printf("end time ：%v;\n", time.Now().Unix())
}

// func writePacketPayload(packet gopacket.Packet) {
// 	// Let’s see if the packet is TCP
// }
