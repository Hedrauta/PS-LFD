$script:sleeptime = 10
$host.UI.RawUI.WindowTitle = "PSLFD: launching"
" ___   ___         _      ___   ___  "
"| _ \ / __|  ___  | |    | __| |   \ "
"|  _/ \__ \ |___| | |__  | _|  | |) |"
"|_|   |___/       |____| |_|   |___/ "
""
""
"Erfasse Firewall-Regel"
""
$FWR1 = Get-NetFirewallRule -Name "PSLFD" -ErrorAction Ignore
$fwav = $false
if ($FWR1 -eq $null) {
    "Keine Firewall-Regel vorhanden. Erstelle neuen Regel"
    ""
    }
else {
    "Firewall-Regel gefunden. Einträge werden bei Bedarf geändert"
    ""
    $fwav = $true
    }

function get_log_ips () {
    $host.UI.RawUI.WindowTitle = "PSLFD: Durchsuche Log"
    $lf_logs = Get-EventLog -LogName Security | Where-Object {$_.EventID -eq 4625} | Where-Object {$_.TimeWritten -ge $((Get-Date).AddDays(-7))} #ansatz zeit
    $host.UI.RawUI.WindowTitle = "PSLFD: Filtere Log"
    $lf_cut = $lf_logs | ForEach-Object { $_.ReplacementStrings[18..19] }
    $lf_ips = $lf_cut | Where-Object { $_ -as [ipaddress] -as [bool]}
    $script:lfd_ips = $($lf_ips | Group-Object | Where-Object {$_.Count -ge 2}).Name #ansatz anzahl logins      
    }

function get_fw_ips () {
    $host.UI.RawUI.WindowTitle = "PSLFD: Erfasse Firewall-IPs"
    sleep -Milliseconds 300 | Out-Null
    $script:FWR = Get-NetFirewallRule -Name "PSLFD" -ErrorAction Ignore
    $script:fw_ips = $(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $FWR).RemoteAddress
    }

function compare_ips ($a,$b) {
    $host.UI.RawUI.WindowTitle = "PSLFD: Vergleiche"
    Sleep -Seconds 1
    $comp = Compare-Object -ReferenceObject $a -DifferenceObject $b | ForEach-Object {
        if ($_.SideIndicator -eq '=>') {
            $_.SideIndicator = 'Old Ban, emtferne von Firewall'
        } elseif ($_.SideIndicator -eq '<=')  {
            $_.SideIndicator = 'New IP, trage in Firewall ein'
        }
        $_
    }
    if ($comp -ne $null) {
        $comp
        }
    sleep -Milliseconds 300
    }

#Ansatz Loop

While (1) {
    get_log_ips
    
    if ($fwav -eq $true) { 
        get_fw_ips
        $fwf = $false
        }
    else {
        "Erstelle nun Firewall-Regel mit neuen IPs"
        New-NetFirewallRule -DisplayName "PowerShell Login Failure Daemon" -Name "PSLFD" -Action Block -RemoteAddress $($lfd_ips) -InterfaceType Any -Direction Inbound
        $fwav = $true
        $script:fwf = $true
        }

    if ($fwf -eq $false) {
        compare_ips $lfd_ips $fw_ips
        Set-NetFirewallRule -Name "PSLFD" -RemoteAddress $lfd_ips | Out-Null
        }
    else {
        $fwf = $false
        }
    
    if ($lfd_ips.Count -eq 0) {
        "Keine IPs in der EreignisAnzeige gefunden. Entferne Firwall-Regel ( keep it clean )"
        Remove-NetFirewallRule -Name "PSLFD"
        $fwav = $false
        }
    $host.UI.RawUI.WindowTitle = "PSLFD: Idle"
    sleep -Seconds $sleeptime
    }
