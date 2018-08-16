/* This command-line program is ment for aiding penetration testers in the enumeration proccess. */
package main

import (
	"fmt"
	"unicode/utf8"
 	"io/ioutil"
 	"os/exec"
 	"strings"
 	"flag"
	"os"
)

/* This function extracts attaker's IP address from ifconfig command output according to the interface that is given as a flag. */
func whatIsMyIP(netInterface string) string{
	ifconfigCmd := exec.Command("ifconfig")
	ifconfigIn, _ := ifconfigCmd.StdinPipe()
	ifconfigOut, _ := ifconfigCmd.StdoutPipe()
	ifconfigCmd.Start()
	ifconfigIn.Write([]byte("ifconfig"))
	ifconfigIn.Close()
	ifconfigBytes, _ := ioutil.ReadAll(ifconfigOut)
	ifconfigCmd.Wait()
	ifconfig := string(ifconfigBytes)
	netInterfaceIndex := strings.Index(ifconfig, netInterface)
	ifconfigTrimmed := ifconfig[netInterfaceIndex:netInterfaceIndex+250]
	inetIndex := strings.Index(ifconfigTrimmed, "inet")
	ifconfigTrimmed2 := ifconfigTrimmed[inetIndex+5:]
	spaceIndex := strings.Index(ifconfigTrimmed2, " ")
	ipAddress := ifconfigTrimmed2[:spaceIndex]	
	return ipAddress
}


/* This function gets attacker's IP address and identifies targets in his current subnet. After that it performs a nmap vulnerability scan against those targets. */
func scanTargetsInSubnet(myIpAddress string) {
	var dots, thirdDotIndex int
	var dot string = "."
	var forWord string = "for"
	for i:= range myIpAddress {
		if (string(myIpAddress[i]) == dot) && (dots <= 2) {
			dots++ }
		if (string(myIpAddress[i]) == dot) && (dots == 3) {
			thirdDotIndex = i }
   	}
	subnetToScan := myIpAddress[:thirdDotIndex] + dot + "0"
	fmt.Println("[+] Alive hosts in " + subnetToScan + "/24 are:")
	nmapCmd := exec.Command("bash", "-c", "nmap -sn " + subnetToScan + "/24")
    	nmapOut, err := nmapCmd.Output()
    	if err != nil {
        	panic(err)
    	}
    	fmt.Println(" ")
    	fmt.Println(string(nmapOut))
	//cut ipaddresses from nmapOut and put it in map afterwards.
	fmt.Println("-------------------------------\n")
	nmapOutput := string(nmapOut)
	forWordIndex := strings.Index(nmapOutput, forWord)
	nmapOutTrimmed := nmapOutput[forWordIndex+4:]
	hostWordIndex := strings.Index(nmapOutTrimmed, "Host")
	aliveHostAddress := nmapOutTrimmed[:hostWordIndex]
	for j := range nmapOutput {
		forWordIndex = strings.Index(nmapOutput, forWord)
		nmapOutTrimmed = nmapOutput[forWordIndex+4:]
		hostWordIndex = strings.Index(nmapOutTrimmed, "Host")
		aliveHostAddress = nmapOutTrimmed[:hostWordIndex]
		//put aliveHostAddress in map
		//targetsMap[j] = aliveHostAddress
		fmt.Println(j)
		fmt.Println(aliveHostAddress)	
		nmapOutTrimmed = strings.Replace(nmapOutTrimmed, aliveHostAddress, "", -1)
	} 
	/*forWordIndex := strings.Index(nmapOutput, forWord)
	nmapOutTrimmed := nmapOutput[forWordIndex+4:]
	hostWordIndex := strings.Index(nmapOutTrimmed, "Host")
	aliveHostAddress := nmapOutTrimmed[:hostWordIndex]
	//put aliveHostAddress in map
	//targetsMap[j] = aliveHostAddress
	fmt.Println(aliveHostAddress)	
	fmt.Println(strings.Replace(nmapOutTrimmed, aliveHostAddress, "", -1))*/
} 


/* This function returns its argument string reversed. */
func reverse(s string) string {
	cs := make([]rune, utf8.RuneCountInString(s))
	i := len(cs)
	for _, c := range s {
		i--
		cs[i] = c
	}
	return string(cs)
}


func main() {	
	interfacePtr := flag.String("interface", "nil", "Name of the interface to use (Required! Run ifconfig before HaGashash in order to choose one).")
	//var myIpAddress string = whatIsMyIP(*interfacePtr) 
	//fmt.Println(myIpAddress)
	//hostPtr := flag.String("host", "nil", "Skip host discovery. Scan only this host (Type its IP address or domain name).")
	//subnetPtr := flag.Bool("subnet", true, "Discover alive hosts in subnet and scan them.")
	/*dnsPtr := flag.Bool("dns", false, "Locate non-contiguous IP space and hostnames against specified domain. (Type "true" or "false").")
	nmap spoof
	nmap decoy*/
	flag.Parse()	
	//whatIsMyIP(*interfacePtr)
	//fmt.Println(interfacePtr)
	//targetsMap := make(map[int]string)	//use this as an argument in scanTargetsInSubnet(targetsMap)
	switch {
	case *interfacePtr == "nil":
		fmt.Println("\n[!] Please specify an interface name. (Ex. -interface=lo)\n\n")	
		flag.PrintDefaults()
		fmt.Println("\n")
		os.Exit(1)
	/*case *hostPtr == "nil":
		//start to scan subnet
		fmt.Println("\n[!] Starting to scan your subnet (/24).\n\n")
		//whatIsMyIP(*interfacePtr)
		scanTargetsInSubnet(myIpAddress)
	/*case *dnsPtr == true:
		//start fierce */
	default:
		//start to scan subnet
		fmt.Println("\n[!] Starting to scan your subnet.\n\n")
		ip := whatIsMyIP(*interfacePtr)
		scanTargetsInSubnet(ip)
	}
	/*start to scan subnet
	fmt.Println("\n[!] Starting to scan your subnet (/24).\n\n")
	whatIsMyIP(*interfacePtr)
	scanTargetsInSubnet(ipAddress) */	
	
}
