/* This command-line program is ment for aiding penetration testers in the enumeration proccess. */
package main

import "fmt"
import "io/ioutil"
import "os/exec"
import "strings"
import "flag"
import "os"

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
	return string(ipAddress)
}


/* This function identifies targets in attacker's current subnet and performs a nmap vulnerability scan against them. */
func scanTargetsInSubnet(myIpAddress string) {
	//Put myIpAddress in string and then trim it from the end until the first dot
	s := myIpAddress	
	fmt.Println(s)
}
	


func main() {	
	interfacePtr := flag.String("interface", "nil", "Name of the interface to use (Required! Run ifconfig before HaGashash in order to choose one).")
	var myIpAddress string = whatIsMyIP(*interfacePtr) 
	fmt.Println(myIpAddress)
	hostPtr := flag.String("host", "nil", "Skip host discovery. Scan only this host (Type its IP address or domain name).")
	subnetPtr := flag.Bool(&myIpAddress, "subnet", true, "Discover alive hosts in subnet and scan them.")
	/*dnsPtr := flag.Bool("dns", false, "Locate non-contiguous IP space and hostnames against specified domain. (Type "true" or "false").")
	nmap spoof
	nmap decoy*/
	flag.Parse()	
	//whatIsMyIP(*interfacePtr)
	//fmt.Println(interfacePtr)
	switch {
	case *interfacePtr == "nil":
		fmt.Println("\n[!] Please specify an interface name. (Ex. -interface=lo)\n\n")	
		flag.PrintDefaults()
		fmt.Println("\n")
		os.Exit(1)
	case *hostPtr == "nil":
		//start to scan subnet
		fmt.Println("\n[!] Starting to scan your subnet (/24).\n\n")
		//whatIsMyIP(*interfacePtr)
		scanTargetsInSubnet(myIpAddress)
	/*case *dnsPtr == true:
		//start fierce
	default:
		fmt.Println("\n[!] Not enough flags in order to start the program. EXITING!\n\n")	
		flag.PrintDefaults()
		fmt.Println("\n")
		os.Exit(1) */	
	}
	/*start to scan subnet
	fmt.Println("\n[!] Starting to scan your subnet (/24).\n\n")
	whatIsMyIP(*interfacePtr)
	scanTargetsInSubnet(ipAddress) */	
	
}
