//
//  Copyright (c) 2020 Oleksandr Tymoshenko <gonzo@bluezbox.com>
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//  1. Redistributions of source code must retain the above copyright
//     notice unmodified, this list of conditions, and the following
//     disclaimer.
//  2. Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
//  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
//  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//  SUCH DAMAGE.
//

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

type ColorScheme int

type Network struct {
    ssid, psk string
    security bool
}

type Tui struct {
    list *widgets.List
    help *widgets.Paragraph
    password *widgets.Paragraph
    listWidth int
}

const (
    noScheme ColorScheme = 0
    darkScheme ColorScheme = 1
    lightScheme ColorScheme = 2
    chaifiMarker = "# CHAIFI: DO NOT EDIT BELOW THIS LINE"
)

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
        if strings.Index(line, chaifiMarker) == 0 {
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

// update wpa_supplicant.conf (if required) and return
// true if new file was written, otherwise false
func updateConfFile(path string, networks []Network) bool {
    file, err := os.OpenFile(path, os.O_RDWR, 0600)
    if err != nil {
        log.Fatal(err)
    }

    newContent := ""
    oldContent := ""

    scanner := bufio.NewScanner(file)
    hasGeneratedSection := false
    for scanner.Scan() {
        line := scanner.Text()
        if ! hasGeneratedSection {
            newContent = newContent + line + "\n"
        }
        oldContent = oldContent + line + "\n"
        if strings.Index(line, chaifiMarker) == 0 {
            hasGeneratedSection = true
        }
    }

    if ! hasGeneratedSection {
        newContent = newContent + chaifiMarker + "\n"
    }

    for _, net := range networks {
        newContent = newContent + genNetworkEntry(net) + "\n"
    }

    if oldContent == newContent {
        return false
    }

    file.Seek(0, io.SeekStart)
    file.Truncate(0)
    file.WriteString (newContent)
    file.Close()

    return true
}

func updateTui(tui *Tui, networks []Network, knownNetworks []Network) {
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
        // substract prefix part and security suffix part
        // scrollbar and borders
        ssidW := tui.listWidth - 5 - 5 - 1 - 2
        spaces := ssidW - len(net.ssid)
        ssid := net.ssid
        for spaces > 0 {
            spaces -= 1
            ssid = ssid + " "
        }
        row := fmt.Sprintf(" [%c] %s %s", foundMark, ssid, security)
        result = append(result, row)
    }
    tui.list.Rows = result
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

func newTui(scheme ColorScheme) *Tui {
    tui := new(Tui)

    // additional colors
    const ColorLightGreen ui.Color = 10
    const ColorLightWhite ui.Color = 15

    tui.list = widgets.NewList()
    tui.list.Title = "[ WiFi Networks ]"
    tui.list.WrapText = false

    // status line with key help
    tui.help = widgets.NewParagraph()
    tui.help.Text = "[a](fg:green) - add network, [x](fg:green) - delete network, [q](fg:green) - quit"
    tui.help.Border = false

    // password entry field
    tui.password = widgets.NewParagraph()
    tui.password.Title = "[ Password ]"
    tui.password.Text = ""
    tui.password.Border = true

    // set color style
    if scheme == darkScheme {
        tui.list.BorderStyle = ui.NewStyle(ui.ColorWhite)
        tui.list.TitleStyle = ui.NewStyle(ui.ColorBlack, ColorLightWhite)
        tui.list.TextStyle = ui.NewStyle(ColorLightWhite)
        tui.list.SelectedRowStyle = ui.NewStyle(ui.ColorBlack, ColorLightWhite)

        tui.help.TextStyle = ui.NewStyle(15)

        tui.password.TextStyle = ui.NewStyle(ColorLightGreen)
        tui.password.BorderStyle = ui.NewStyle(ui.ColorGreen)
        tui.password.TitleStyle = ui.NewStyle(ColorLightGreen)
    } else if scheme == lightScheme {
        tui.list.BorderStyle = ui.NewStyle(ui.ColorWhite)
        tui.list.TitleStyle = ui.NewStyle(ui.ColorBlack, ColorLightWhite)
        tui.list.TextStyle = ui.NewStyle(ui.ColorBlack)
        tui.list.SelectedRowStyle = ui.NewStyle(ui.ColorWhite, ui.ColorBlack)

        tui.help.TextStyle = ui.NewStyle(ui.ColorBlack)

        tui.password.TextStyle = ui.NewStyle(ColorLightGreen)
        tui.password.BorderStyle = ui.NewStyle(ui.ColorGreen)
        tui.password.TitleStyle = ui.NewStyle(ColorLightGreen)
    }

    return tui
}

func resizeTui(tui *Tui) {
    uiW, uiH := ui.TerminalDimensions()

    listW := uiW
    listH := uiH - 3

    if listW > 80 {
        listW = 80
    }

    if listH > 25 {
        listH = 25
    }

    // store width for rows padding
    tui.listWidth = listW

    x := (uiW - listW) / 2
    y := (uiH - listH) / 2

    tui.list.SetRect(x, y, x + listW, y + listH)

    tui.help.SetRect(x, y + listH + 1, x + listW, y + listH + 2)

    passwordW := listW * 3 / 4
    passwordH := 3
    x = (uiW - passwordW) / 2
    y = (uiH - passwordH) / 2
    tui.password.SetRect(x, y, x + passwordW, y + passwordH)
}

func main() {
    var iface string
    var wpaConfFile string
    var restartNetwork bool
    var useLightTheme bool

    flag.StringVar(&iface, "i", "wlan0", "wireless interface")
    flag.StringVar(&wpaConfFile, "f", "/etc/wpa_supplicant.conf", "path to wpa_supplicant.conf")
    flag.BoolVar(&restartNetwork, "r", false, "restart netif service if config has changed")
    flag.BoolVar(&useLightTheme, "l", false, "use light color scheme")

    flag.Parse()

    networks := listScan(iface)

    // load known networks from the config file
    knownNetworks, err := loadConfFile(wpaConfFile)
    if err != nil {
        log.Fatal(err)
    }

    // Initialize and procede with UI
    if err := ui.Init(); err != nil {
            log.Fatalf("failed to initialize termui: %v", err)
    }

    // save edited known networks on exit
    defer func() {
        ui.Close()
        haveNewConfig := updateConfFile(wpaConfFile, knownNetworks)
        if haveNewConfig {
            if restartNetwork {
                fmt.Println ("new config, restarting network...")
                cmd := exec.Command("service", "netif", "restart", iface)
                cmd.Run()
            } else {
                fmt.Printf ("new config, please run \"service netif restart %s\" manually\n", iface)
            }
        } else {
            fmt.Println ("config file was not changed")
        }
    }()

    scheme := darkScheme
    if useLightTheme {
        scheme = lightScheme
    }
    tui := newTui(scheme)
    resizeTui(tui)
    updateTui(tui, networks, knownNetworks)

    ui.Render(tui.list)
    ui.Render(tui.help)

    passwordPromptVisible := false
    password := ""
    uiEvents := ui.PollEvents()
    for {
        e := <-uiEvents
        if e.ID == "<Resize>" {
            ui.Clear()
            resizeTui(tui)
            updateTui(tui, networks, knownNetworks)
            ui.Render(tui.list)
            ui.Render(tui.help)
            if passwordPromptVisible {
                ui.Render(tui.password)
            }
            continue
        }

        if passwordPromptVisible {
            if len(e.ID) == 1 {
                password = password + e.ID
            } else {
                switch e.ID {
                case "<Enter>":
                    // update or add new network
                    selectedNet := networks[tui.list.SelectedRow]
                    selectedNet.psk = password
                    knownNetworks = addNetwork(knownNetworks, selectedNet)
                    updateTui(tui, networks, knownNetworks)
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
            tui.password.Text = password
        } else {
            switch e.ID {
            case "q", "<C-c>":
                return
            case "j", "<Down>":
                tui.list.ScrollDown()
            case "k", "<Up>":
                tui.list.ScrollUp()
            case "<C-d>":
                tui.list.ScrollHalfPageDown()
            case "<C-u>":
                tui.list.ScrollHalfPageUp()
            case "<C-f>", "<PageDown>":
                tui.list.ScrollPageDown()
            case "<C-b>", "<PageUp>":
                tui.list.ScrollPageUp()
            case "<Home>":
                tui.list.ScrollTop()
            case "<End>":
                tui.list.ScrollBottom()
            case "a":
                selectedNet := networks[tui.list.SelectedRow]
                if selectedNet.security {
                    passwordPromptVisible = true
                } else {
                    knownNetworks = addNetwork(knownNetworks, selectedNet)
                    updateTui(tui, networks, knownNetworks)
                }
            case "x":
                selectedNet := networks[tui.list.SelectedRow]
                // find and delete SSID from the list of known networks
                for i, net := range knownNetworks {
                    if net.ssid == selectedNet.ssid {
                        knownNetworks = append(knownNetworks[:i], knownNetworks[i+1:]...)
                    }
                }
                updateTui(tui, networks, knownNetworks)
            }
        }

        if passwordPromptVisible {
            ui.Render(tui.password)
        } else {
            ui.Render(tui.list)
        }
    }
}
