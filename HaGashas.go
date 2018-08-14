/* This progtam is ment for aiding penetration testers in the enumeration proccess. */
package main

import "fmt"
import "io/ioutil"
import "os/exec"
import "strings"

/* This function responsible on program's flags. */
func flags()



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
	whatIsMyIP("enp0s3")
	
}
