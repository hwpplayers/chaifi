// +build ignore

package main

import (
    "strings"
    "fmt"
    "bytes"
    "os/exec"
)

type Network struct {
    ssid, bssid string
}

func listScan(iface string) []Network {
    cmd := exec.Command("ifconfig", "-v", iface, "list", "scan")
    cmdOutput := &bytes.Buffer{}
    cmd.Stdout = cmdOutput
    err := cmd.Run()
    if err != nil {
        return nil
    }
    output := string(cmdOutput.Bytes())
    lines := strings.Split(output, "\n")
    if len(lines) < 1 {
        return nil
    }
    header := lines[0]
    lines = lines[1:]
    ssidEnd := strings.Index(header, "BSSID") - 1
    if ssidEnd < 0 {
        return nil
    }

    result := []Network{}
    for _, line := range lines {
        if len(line) < ssidEnd + 1 {
            continue
        }
        ssid := line[:ssidEnd]
        ssid = strings.Trim(ssid, " ")
        bssid := line[ssidEnd + 1:ssidEnd + 18]
        network := Network {ssid: ssid, bssid: bssid}
        result = append(result, network)
    }
    return result
}

func main() {
    networks := listScan("wlan0")
    fmt.Printf("Total networks: %d\n", len(networks))
    for _, net := range networks {
        fmt.Printf("===> [%s] %s\n", net.bssid, net.ssid)
    }
}
