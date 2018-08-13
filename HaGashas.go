/* This progtam is ment for aiding penetration testers in the enumeration proccess. */
package main

import "fmt"
import "io/ioutil"
import "os/exec"

/* This function extracts attaker's IP address from ifconfig command output */
func whatIsMyIP() {
	ifconfigCmd := exec.Command("ifconfig")
	ifconfigIn, _ := ifconfigCmd.StdinPipe()
	ifconfigOut, _ := ifconfigCmd.StdoutPipe()
	ifconfigCmd.Start()
	ifconfigIn.Write([]byte("ifconfig"))
	ifconfigIn.Close()
	ifconfigBytes, _ := ioutil.ReadAll(ifconfigOut)
	ifconfigCmd.Wait()
	s := []string{string(ifconfigBytes)} //slice it
	fmt.Println(s)

	
}



/* This function identifies targets in my current subnet. 
func identifyTargetsInSubnet */
	


func main() {
	whatIsMyIP()
	
}
