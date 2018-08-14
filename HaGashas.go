/* This command-line program is ment for aiding penetration testers in the enumeration proccess. */
package main

import "fmt"
import "io/ioutil"
import "os/exec"
import "strings"
import "flag"
import "os"

/* This function extracts attaker's IP address from ifconfig command output according to the interface that is given as a flag. */
func whatIsMyIP(netInterface string) {
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
	fmt.Println(ipAddress)
}


/* This function identifies targets in my current subnet. 
func identifyTargetsInSubnet */
	


func main() {	
	interfacePtr := flag.String("interface", "nil", "Name of the interface to use (Run ifconfig before HaGashash in order to choose one).")
	hostPtr := flag.String("host", "nil", "Skip host discovery. Scan only this host (Type its IP address or domain name).")
	subnetPtr := flag.String(&ipAddress, "none", ipAddress, "Discover alive hosts in subnet and scan them. (Default - scans /24).")
	/*dnsPtr := flag.Bool("fork", false, "Locate non-contiguous IP space and hostnames against specified domain. (Type "true" or "false").")
	/*nmap spoof
	nmap decoy*/
	flag.Parse()	
	//whatIsMyIP(*interfacePtr)
	//fmt.Println(interfacePtr)
	switch {
	case *interfacePtr == "nil":
		fmt.Println("\nPlease specify an interface name. (Ex. -interface=lo)\n\n")	
		flag.PrintDefaults()
		fmt.Println("\n")
		os.Exit(1)
	case *hostPtr == "nil":
		fmt.Println("\nPlease specify a target. (Ex. -host=example.com or -host=127.0.0.1)\n\n")	
		flag.PrintDefaults()
		fmt.Println("\n")
		os.Exit(1)
	case *subnetPtr == "nil":
		fmt.Println("\nPlease specify a target. (Ex. -host=example.com or -host=127.0.0.1)\n\n")	
		flag.PrintDefaults()
		fmt.Println("\n")
		os.Exit(1)
	}
	
}
