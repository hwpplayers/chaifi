// +build ignore

package main

import (
    "bufio"
    "bytes"
    "errors"
    "io"
    "fmt"
    "log"
    "os"
    "os/exec"
    "strings"
)

const shyfi_marker = "# SHYFI: DO NOT EDIT BELOW THIS LINE"

type Network struct {
    ssid, bssid, psk string
    wpa bool
}

// simplified escape algorithm: escape backslash(\) and double quotes
func escapeString(val string) string {
    escaped := strings.ReplaceAll(val, "\\", "\\\\")
    escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
    return escaped
}

// simplified un-escape algorithm: un-escape backslash(\) and double quotes
func unescapeString(val string) (string, error) {
    if val == "" {
        return val, nil
    }

    l := len(val)
    if val[0] == '"' {
        if val[l-1] != '"' {
            return val, errors.New("Unbalanced quotes in string value")
        }
    } else {
        // this is bare string
        return val, nil
    }

    return val[1:l-1], nil
}

// Generate single network entry for wpa_supplicant.conf
func genNetworkEntry(network Network) string {
    result := ""
    result += "network={\n"
    if network.ssid != "" {
        result += fmt.Sprintf("    ssid=\"%s\"\n", escapeString(network.ssid))
    } else if network.bssid != "" {
        result += fmt.Sprintf("    bssid=\"%s\"\n", escapeString(network.bssid))
    }

    keyMgmt := "NONE"
    if network.wpa {
        keyMgmt = "WPA-PSK"
    }
    result += fmt.Sprintf("    key_mgmt=%s\n", keyMgmt)

    if network.psk != "" {
        result += fmt.Sprintf("    psk=\"%s\"\n", escapeString(network.psk))
    }

    result += "}\n"
    return result
}

func loadConfFile(path string) ([]Network, error) {
    result := []Network{}

    file, err := os.Open(path)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    inGeneratedSection := false
    var network *Network = nil
    for scanner.Scan() {
        line := scanner.Text()
        if strings.Index(line, shyfi_marker) == 0 {
            inGeneratedSection = true
            continue
        }
        if !inGeneratedSection {
            continue
        }
        line = strings.Trim(line, " ")
        if len(line) == 0 {
            continue
        }

        if line == "network={" {
            network = & Network{}
            continue
        }

        if line == "}" {
            result = append(result, *network)
            continue
        }

        // Split key/value
        parts := strings.SplitN(line, "=", 2)
        if len(parts) != 2 {
        }

        key := parts[0]
        value := parts[1]
        value, err = unescapeString(value)
        if err != nil {
        }
        switch key {
        case "ssid":
            network.ssid = value
        case "bssid":
            network.bssid = value
        case "psk":
            network.psk = value
        case "key_mgmt":
            network.wpa = value == "WPA-PSK"
        default:
            // TODO: raise error
        }
    }

    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }

    return result, nil
}

func listScan(iface string) []Network {
    result := []Network{}
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
        return result
    }
    header := lines[0]
    lines = lines[1:]
    ssidEnd := strings.Index(header, "BSSID") - 1
    if ssidEnd < 0 {
        return result
    }

    for _, line := range lines {
        if len(line) < ssidEnd + 1 {
            continue
        }
        ssid := line[:ssidEnd]
        ssid = strings.Trim(ssid, " ")
        bssid := line[ssidEnd + 1:ssidEnd + 18]
        network := Network {ssid: ssid, bssid: bssid}
        result = append(result, network)

        wpaPos := strings.Index(line, "WPA<") - 1
        if wpaPos > 0 {
            network.wpa = true
        }
    }

    return result
}

func updateConfFile(path string, networks []Network) {
    file, err := os.OpenFile(path, os.O_RDWR, 0600)
    if err != nil {
        log.Fatal(err)
    }

    newContent := ""

    scanner := bufio.NewScanner(file)
    hasGeneratedSection := false
    for scanner.Scan() {
        line := scanner.Text()
        newContent = newContent + line + "\n"
        if strings.Index(line, shyfi_marker) == 0 {
            hasGeneratedSection = true
            break
        }
    }

    if ! hasGeneratedSection {
        newContent = newContent + shyfi_marker + "\n"
    }

    for _, net := range networks {
        newContent = newContent + genNetworkEntry(net) + "\n"
    }

    file.Seek(0, io.SeekStart)
    file.Truncate(0)
    file.WriteString (newContent)
    file.Close()
}

func main() {
    networks := listScan("wlan0")
    fmt.Printf("Total networks: %d\n", len(networks))
    for _, net := range networks {
        fmt.Printf("===> [%s] %s\n", net.bssid, net.ssid)
    }

    knownNetworks, err := loadConfFile("wpa_supplicant.conf.orig")
    if err != nil {
        log.Fatal(err)
    }

    updateConfFile("wpa_supplicant.conf", knownNetworks)
}
