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

/* This function checks if all tools that are necessary for running properly, exist in system.
The function gets a slice of necessary tools and print if they exist or not. 
func checkIfNecessaryToolsAreExist() {
    path, err := exec.LookPath("ls")
    if err != nil {
        fmt.Printf("didn't find 'ls' executable\n")
    } else {
        fmt.Printf("'ls' executable is in '%s'\n", path)
    }
}


/* This function extracts attacker's IP address from ifconfig command output according to the interface that is given as a flag.
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
} */

/* This recursive function extracts IP addresses from nmap -sn output. The function gets command's output and a slice of target IPs. 
It returns slice of target IPs updated (appended) *
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
It identifies targets in his current subnet, saves those addresses in a slice of target and prints them. *
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
} */

/* This function performs a nmap TCP/UDP/vulnerability scan on target IP. 
func nmapVulnScan(targetIP string, xmlPath string) {
	fmt.Println("\n\n[!] Starting to scan " + targetIP + " for TCP ports.")
	nmapCmd := exec.Command("bash", "-c", "nmap -sS -p- -T4 -Pn -vv -oX " + xmlPath + "/TCPxml " + targetIP)
    	err := nmapCmd.Start()
    	if err != nil {
        	panic(err)
    	}
	err = nmapCmd.Wait()	
	if err != nil {
        	panic(err)
    	}
    	//fmt.Println("\n")
	//call xmlParser
	parseXML(xmlPath + "/TCPxml")
	//Vuln scan those ports
	fmt.Println("\n\n[!] Starting to scan " + targetIP + " for UDP ports.")
	nmapCmd = exec.Command("bash", "-c", "nmap -sU -p- -T4 -Pn -vv -oX " + xmlPath + "/UDPxml " + targetIP)
    	err = nmapCmd.Start()
    	if err != nil {
        	panic(err)
    	}
	err = nmapCmd.Wait()	
	if err != nil {
        	panic(err)
    	}
    	fmt.Println("\n")
}

/* This function parses the TCPxml and UDPxml files that are created in nmapVulnScan(). 
func parseXML(xmlPath string) {
	type Targets struct {
		XMLName xml.Name `xml:"targets"`
		Address []Addresses `xml:"addresses"`
   		//os string
   		Port []Ports `xml:"ports"`
		//vulnerability string
	}
	type Addresses struct {
		XMLName xml.Name `xml:"addresses"`
		Address string `xml:"addr,attr"`
		Addresstype string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
	}
	type Ports struct {
		XMLName xml.Name `xml:"ports"`
		Portid int `xml:"portid,attr"`
		Protocol string `xml:"protocol,attr"`
		State string `xml:"state,attr"`
		
	} 
	// Open our xmlFile
	xmlFile, err := os.Open(xmlPath + "/TCPxml")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Successfully Opened " + xmlPath + "/TCPxml")
	// defer the closing of our xmlFile so that we can parse it later on
	defer xmlFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := ioutil.ReadAll(xmlFile)

	// we initialize our Targets array
	var targetim Targets
	// we unmarshal our byteArray which contains our
	// xmlFiles content into 'targets' which we defined above
	xml.Unmarshal(byteValue, &targetim)
	//fmt.Println(targetsArray)
	// we iterate through every user within our users array and
	// print out the user Type, their name, and their facebook url
	// as just an example
	fmt.Println(targetim.Address)
	/*for i := 0; i < len(targetim.Targets); i++ {
		fmt.Println("Address: " + targetim.Targets[i].Address)
		fmt.Println("Port: " + targetim.Targets[i].Port)
	} */
}

/* This function creates a directory if it does not exist. Otherwise do nothing. 
func createDirIfNotExist(dir string) {
      if _, err := os.Stat(dir); os.IsNotExist(err) {
              err = os.MkdirAll(dir, 0755)
              if err != nil {
                      panic(err)
              }
      }
}

/*type address struct {
		XMLName xml.Name `xml:"address"`
		Addr string `xml:"addr,attr"`
		Addrtype string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
}
type port struct {
		XMLName xml.Name `xml:"port"`
		Portid int `xml:"portid,attr"`
		Protocol string `xml:"protocol,attr"`
		State string `xml:"state,attr"`
		
}
type Targets struct {
		XMLName xml.Name `xml:"Targets"`
		Address []address
   		//os string
   		Port []port
		//vulnerability string
} */

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
		var targetim Targets
		ip := whatIsMyIP(*interfacePtr)
		tars := aliveHostsInSubnet(targets, ip)
		for i:= range tars {
			path := "/home/" + userEnvVar + "/HaGashash_Projects/" + *projectNamePtr + "/" + strings.Trim(tars[i],"'$'\n'")
			createDirIfNotExist(path)
			nmapVulnScan(strings.Trim(tars[i],"'$'\n'"),path)
			parseXML(path)						  			
		}
}
		
}
