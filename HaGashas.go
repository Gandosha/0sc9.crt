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

/* This function extracts attacker's IP address from ifconfig command output according to the interface that is given as a flag. */
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

/* This recursive function extracts IP addresses from nmap -sn output. The function gets command's output and a slice of target IPs. 
It returns slice of target IPs updated (appended) */
func extractIPs(sliceOfTargets []string, nmapCmdOutput string) []string {
	var forWord string = "for"
	forWordIndex := strings.Index(nmapCmdOutput, forWord)
	if forWordIndex != -1 {
		nmapOutTrimmed := nmapCmdOutput[forWordIndex+4:]
		hostWordIndex := strings.Index(nmapOutTrimmed, "Host")
		aliveHostAddress := nmapOutTrimmed[:hostWordIndex]
		nmapOutTrimmed = strings.Replace(nmapOutTrimmed, aliveHostAddress, "\n", -1) 
		sliceOfTargets = append(sliceOfTargets, aliveHostAddress)
		return extractIPs(sliceOfTargets, nmapOutTrimmed) 
	} else {
		return sliceOfTargets 
	}		 			
}


/* This function gets empty slice of target IPs and attacker's IP address. 
It identifies targets in his current subnet, saves those addresses in a slice of target and prints them. */
func aliveHostsInSubnet(ipAddressesSlice []string, myIpAddress string) {
	var dots, thirdDotIndex int
	var dot string = "."
	for i := range myIpAddress {
		if (string(myIpAddress[i]) == dot) && (dots <= 2) {
			dots++ }
		if (string(myIpAddress[i]) == dot) && (dots == 3) {
			thirdDotIndex = i }
   	}
	subnetToScan := myIpAddress[:thirdDotIndex] + dot + "0"
	nmapCmd := exec.Command("bash", "-c", "nmap -sn " + subnetToScan + "/24")
    	nmapOut, err := nmapCmd.Output()
    	if err != nil {
        	panic(err)
    	}
    	fmt.Println(" ")
	nmapOutput := string(nmapOut)
	targets := extractIPs(ipAddressesSlice, nmapOutput)
	fmt.Println("[+] Alive hosts in " + subnetToScan + "/24 are:\n")
	for k := range targets {
		fmt.Println(targets[k])
   	}
} 

/* This function performs a nmap TCP/UDP/vulnerability scan on slice of target IPs*/
func nmapVulnScan(targetsSlice []string)
//Work with struct target https://golang.org/pkg/encoding/xml/ (see "func Unmarshal")
//Export nmap's output to XML format.
//Take port numbers and append to a TCP and UDP slices
//Vuln scan those ports and export in XML 



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
	var targets []string	
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
		fmt.Println("\n[!] Starting to scan your subnet.\n")
		ip := whatIsMyIP(*interfacePtr)
		aliveHostsInSubnet(targets, ip)
	}
	/*start to scan subnet
	fmt.Println("\n[!] Starting to scan your subnet (/24).\n\n")
	whatIsMyIP(*interfacePtr)
	scanTargetsInSubnet(ipAddress) */	
	
}
