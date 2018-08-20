/* This command-line program is ment for aiding penetration testers in the enumeration proccess. */
package main

import (
	"fmt"
	"encoding/xml"
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
func aliveHostsInSubnet(ipAddressesSlice []string, myIpAddress string) []string {
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
	return targets
	//return fmt.Println(targets)
} 

/* This function performs a nmap TCP/UDP/vulnerability scan on target IP. */
func nmapVulnScan(targetIP string) {
//Work with struct target https://golang.org/pkg/encoding/xml/ (see "func Unmarshal")
//Perform basic tcp/udp scans on all ports. Then take port numbers and append to a TCP and UDP slices and export in XML
//Vuln scan those ports and export in XML
	fmt.Println("\n\n[!] Starting to scan " + targetIP + " for TCP ports.")
	nmapTCPscanCmd := exec.Command("bash", "-c", "sudo nmap -sS -p- -T4 -Pn -vv -oX ~/Desktop/" + targetIP + "/TCPxml " + targetIP)
    	nmapTCPscanCmdOut, err := nmapTCPscanCmd.Output()
	if err != nil {
        	panic(err)
    	}	
	nmapTCPscanCmdOutput := string(nmapTCPscanCmdOut)
	fmt.Println("\n\n[!] Starting to scan " + targetIP + " for UDP ports.")
	nmapUDPscanCmd := exec.Command("bash", "-c", "sudo nmap -sU -p- -T4 -Pn -vv -oX ~/Desktop/" + targetIP + "/UDPxml " + targetIP)
    	nmapUDPscanCmdOut, err := nmapUDPscanCmd.Output()
	if err != nil {
        	panic(err)
    	}	
	nmapUDPscanCmdOutput := string(nmapUDPscanCmdOut)
	//Parse Those XMLs and put values in struct
	v := Targets{}
	err1 := xml.Unmarshal([]byte(nmapTCPscanCmdOutput), &v)
	if err1 != nil {
		fmt.Printf("error: %v", err1)
		return
	}
	err2 := xml.Unmarshal([]byte(nmapUDPscanCmdOutput), &v)
	if err2 != nil {
		fmt.Printf("error: %v", err2)
		return
	}
	fmt.Printf("Address: %#v\n", v.Address)
	fmt.Printf("Port: %q\n", v.Port)
}

/* Create a directory if it does not exist. Otherwise do nothing. */
func createDirIfNotExist(dir string) {
      if _, err := os.Stat(dir); os.IsNotExist(err) {
              err = os.MkdirAll(dir, 0755)
              if err != nil {
                      panic(err)
              }
      }
}


type address struct {
		addr string `xml:"addr,attr"`
		addrtype string `xml:"addrtype,attr"`
		vendor string `xml:"vendor,attr"`
}
	type port struct {
		portid int `xml:"portid,attr"`
		protocol string `xml:"protocol,attr"`
		state string `xml:"state,attr"`
		
}
	type Targets struct {
		Address []address
   		//os string
   		Port []port
		//vulnerability string
} 

func main() {	
	userEnvVar := os.Getenv("SUDO_USER")
	projectNamePtr := flag.String("project", "nil", "Name of the project. (Required! It will create project's folder in /home/" + userEnvVar + "/HaGashash_Temp/).")
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
	//v := Targets{}	
	//whatIsMyIP(*interfacePtr)
	//fmt.Println(interfacePtr)
	//targetsMap := make(map[int]string)	//use this as an argument in scanTargetsInSubnet(targetsMap)
	switch {
	case *interfacePtr == "nil":
		fmt.Println("\n[!] Please specify an interface name. (Ex. -interface=lo)\n\n")	
		flag.PrintDefaults()
		fmt.Println("\n")
		os.Exit(1)
	case *projectNamePtr == "nil":
		fmt.Println("\n[!] Please specify a name for the project. (Ex. -project=example.com)\n\n")	
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
		tars := aliveHostsInSubnet(targets, ip)
		/* binary, lookErr := exec.LookPath("mkdir")
		//env := os.Environ()
    		if lookErr != nil {
        		panic(lookErr)
    		} */
		fmt.Println("tars: \n",tars)
		for i:= range tars {
			fmt.Println("ip: ",tars[i])
			path := "/home/" + userEnvVar + "/HaGashash_Projects/" + *projectNamePtr + "/" + strings.Trim(tars[i],"'$'\n'")
			fmt.Println("path: ",path)
			createDirIfNotExist(path)
		}	  			
}
}
