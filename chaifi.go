package main

import (
    "bufio"
    "bytes"
    "errors"
    "io"
    "flag"
    "fmt"
    "log"
    "os"
    "os/exec"
    "sort"
    "strings"

    ui "github.com/gizak/termui/v3"
    "github.com/gizak/termui/v3/widgets"
)

const chaifi_marker = "# CHAIFI: DO NOT EDIT BELOW THIS LINE"

type Network struct {
    ssid, psk string
    security bool
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
    }

    keyMgmt := "NONE"
    if network.security {
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
        if strings.Index(line, chaifi_marker) == 0 {
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
        case "psk":
            network.psk = value
        case "key_mgmt":
            network.security = value == "WPA-PSK"
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

        // For now just skip networks with empty SSID
        if ssid == "" {
            continue
        }

        found := false
        for _, n := range result {
            if n.ssid == ssid {
                found = true
                break
            }
        }
        if found {
            continue
        }

        security := false
        wpaPos := strings.Index(line, "WPA<") - 1
        rsnPos := strings.Index(line, "RSN<") - 1
        if wpaPos > 0 || rsnPos > 0 {
            security = true
        }
        network := Network {ssid: ssid, security: security}
        result = append(result, network)
    }

    sort.Slice(result, func(i, j int) bool {
       return result[i].ssid < result[j].ssid
    })

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
        if strings.Index(line, chaifi_marker) == 0 {
            hasGeneratedSection = true
            break
        }
    }

    if ! hasGeneratedSection {
        newContent = newContent + chaifi_marker + "\n"
    }

    for _, net := range networks {
        newContent = newContent + genNetworkEntry(net) + "\n"
    }

    file.Seek(0, io.SeekStart)
    file.Truncate(0)
    file.WriteString (newContent)
    file.Close()
}

func generateUIRows(networks []Network, knownNetworks []Network) []string {
    result := []string{}

    for _, net := range networks {
        if net.ssid == "" {
            continue
        }
        found := false
        for _, n := range knownNetworks {
            if n.ssid == net.ssid {
                found = true
                break
            }
        }
        foundMark := ' '
        if found {
            foundMark = '+'
        }
        security := ""
        if net.security {
            security = "WPA"
        }
        row := fmt.Sprintf(" [%c] %-67s %s", foundMark, net.ssid, security)
        result = append(result, row)
    }

    return result
}

func addNetwork(networks []Network, newNet Network) []Network {
    found := false
    // check if the network is in the known list and if not - add it
    for _, net := range networks {
        if net.ssid == newNet.ssid {
            found = true
            break
        }
    }
    if ! found {
        networks = append(networks, newNet)
    }

    return networks
}

func main() {
    var iface string
    var wpa_conf_file string

    flag.StringVar(&iface, "i", "wlan0", "wireless interface")
    flag.StringVar(&wpa_conf_file, "f", "/etc/wpa_supplicant.conf", "path to wpa_supplicant.conf")

    flag.Parse()

    networks := listScan(iface)

    // load known networks from the config file
    knownNetworks, err := loadConfFile(wpa_conf_file)
    if err != nil {
        log.Fatal(err)
    }

    // save edited known networks on exit
    defer func() {
        updateConfFile(wpa_conf_file, knownNetworks)
    }()

    // Initialize and procede with UI
    if err := ui.Init(); err != nil {
            log.Fatalf("failed to initialize termui: %v", err)
    }
    defer ui.Close()

    // additional colors
    const ColorLightGreen ui.Color = 10
    const ColorLightWhite ui.Color = 15

    l := widgets.NewList()
    l.Title = "[ WiFi Networks ]"
    l.Rows = generateUIRows(networks, knownNetworks)
    l.BorderStyle = ui.NewStyle(ui.ColorWhite)
    l.TitleStyle = ui.NewStyle(ui.ColorBlack, ColorLightWhite)
    l.TextStyle = ui.NewStyle(ColorLightWhite)
    l.SelectedRowStyle = ui.NewStyle(ui.ColorBlack, ColorLightWhite)
    l.WrapText = false
    uiW, uiH := ui.TerminalDimensions()
    listW := 80
    listH := 25
    x := (uiW - listW) / 2
    y := (uiH - listH) / 2
    l.SetRect(x, y, x + listW, y + listH)

    // status line with key help
    p0 := widgets.NewParagraph()
    p0.TextStyle = ui.NewStyle(15)
    p0.Text = "[a](fg:green) - add network, [x](fg:green) - delete network, [q](fg:green) - quit"
    p0.SetRect(x, y + listH + 1, x + listW, y + listH + 2)
    p0.Border = false

    // password entry field
    pwInput := widgets.NewParagraph()
    pwInput.TextStyle = ui.NewStyle(ColorLightGreen)
    pwInput.BorderStyle = ui.NewStyle(ui.ColorGreen)
    pwInput.TitleStyle = ui.NewStyle(ColorLightGreen)
    pwInput.Title = "[ Password ]"
    pwInput.Text = ""
    passwordW := 60
    passwordH := 3
    x = (uiW - passwordW) / 2
    y = (uiH - passwordH) / 2
    pwInput.SetRect(x, y, x + passwordW, y + passwordH)
    pwInput.Border = true

    ui.Render(l)
    ui.Render(p0)

    passwordPromptVisible := false
    password := ""
    uiEvents := ui.PollEvents()
    for {
        e := <-uiEvents
        if passwordPromptVisible {
            if len(e.ID) == 1 {
                password = password + e.ID
            } else {
                switch e.ID {
                case "<Enter>":
                    // update or add new network
                    selectedNet := networks[l.SelectedRow]
                    selectedNet.psk = password
                    knownNetworks = addNetwork(knownNetworks, selectedNet)
                    l.Rows = generateUIRows(networks, knownNetworks)
                    passwordPromptVisible = false
                    password = ""
                case "<Escape>", "<C-c>":
                    passwordPromptVisible = false
                    password = ""
                case "<C-u>":
                    password = ""
                case "<Backspace>", "<C-<Backspace>>":
                    password = password[:len(password)-1]
                case "<Space>":
                    password = password + " "
                }
            }
            pwInput.Text = password
        } else {
            switch e.ID {
            case "q", "<C-c>":
                return
            case "j", "<Down>":
                l.ScrollDown()
            case "k", "<Up>":
                l.ScrollUp()
            case "<C-d>":
                l.ScrollHalfPageDown()
            case "<C-u>":
                l.ScrollHalfPageUp()
            case "<C-f>", "<PageDown>":
                l.ScrollPageDown()
            case "<C-b>", "<PageUp>":
                l.ScrollPageUp()
            case "<Home>":
                l.ScrollTop()
            case "<End>":
                l.ScrollBottom()
            case "a":
                selectedNet := networks[l.SelectedRow]
                if selectedNet.security {
                    passwordPromptVisible = true
                } else {
                    knownNetworks = addNetwork(knownNetworks, selectedNet)
                    l.Rows = generateUIRows(networks, knownNetworks)
                }
            case "x":
                selectedNet := networks[l.SelectedRow]
                // find and delete SSID from the list of known networks
                for i, net := range knownNetworks {
                    if net.ssid == selectedNet.ssid {
                        knownNetworks = append(knownNetworks[:i], knownNetworks[i+1:]...)
                    }
                }
                l.Rows = generateUIRows(networks, knownNetworks)
            }
        }

        if passwordPromptVisible {
            ui.Render(pwInput)
        } else {
            ui.Render(l)
        }
    }
}
