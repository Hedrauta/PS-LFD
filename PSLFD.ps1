# Variables for script
$script:sleeptime = 10 # Best: 10, Paranoid: 1, Save performance: 30
$script:failed_logins = 2 # number of failed logins via RDP before ban
$script:Days_ban = 7 # Days of Eventlog and Duration of Ban
# Please edit the values above. 
# Do not edit below, if you don't know, what the code does
# Seriously, it could harm ya firewall, if you're not experienced

$host.UI.RawUI.WindowTitle = "PSLFD: launching"
" ___   ___         _      ___   ___  "
"| _ \ / __|  ___  | |    | __| |   \ "
"|  _/ \__ \ |___| | |__  | _|  | |) |"
"|_|   |___/       |____| |_|   |___/ "
""
""
"Get Firewall Rules"
""
$FWR1 = Get-NetFirewallRule -Name "PSLFD" -ErrorAction Ignore
if ($FWR1 -eq $null) {
    "No firewall-rule found. Creating new rule called 'PowerShell Login Failure Daemon'"
    $fwav = $false
    ""
    }
else {
    "PSLFD-firewall-rule found. Changing entries on behaviour"
    ""
    $fwav = $true
    }
"From now, the PSLFD-Actions will be written in the Windows Title"
"To Stop the script, press CTRL+C or close this Windows"
""
# Functions
function get_log_ips () {
    $host.UI.RawUI.WindowTitle = "PSLFD: Searching Log"
    $lf_logs = Get-EventLog -LogName Security | Where-Object {$_.EventID -eq 4625} | Where-Object {$_.TimeWritten -ge $((Get-Date).AddDays( - $Days_ban))} #ansatz zeit
    $host.UI.RawUI.WindowTitle = "PSLFD: Filtering Log"
    $lf_cut = $lf_logs | ForEach-Object { $_.ReplacementStrings[18..19] }
    $lf_ips = $lf_cut | Where-Object { $_ -as [ipaddress] -as [bool]}
    $script:lfd_ips = $($lf_ips | Group-Object | Where-Object {$_.Count -ge $failed_logins}).Name #ansatz anzahl logins
    if ($lfd_ips.Count -eq 0) {
        $script:lfd_ips = @('')
        }
    }

function get_fw_ips () {
    $host.UI.RawUI.WindowTitle = "PSLFD: Fetching Firewall-IPs"
    sleep -Milliseconds 300 | Out-Null
    $script:FWR = Get-NetFirewallRule -Name "PSLFD" -ErrorAction Ignore
    $script:fw_ips = $(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $FWR).RemoteAddress
    }

function compare_ips ($a,$b) {
    $host.UI.RawUI.WindowTitle = "PSLFD: Compare log with firewall"
    Sleep -Seconds 1
    $script:comp = Compare-Object -ReferenceObject $lfd_ips -DifferenceObject $fw_ips | Select-Object @{Name="IPAdress";Expression={$_.InputObject}},@{Name="Action";Expression={$_.SideIndicator}} | ForEach-Object {
        if ($_.Action -eq '=>' -and $_.IPAdress -eq "") {
            $_.Action = 'No Rule found, creating Rule'
        } elseif ($_.Action -eq '=>') {
            $_.Action = 'Old Ban, remove from firewall'
        } elseif ($_.Action -eq '<=' -and $_.IPAdress -eq "") {
            $_.Action = 'No IPs found. Removing Rule'
        } elseif ($_.Action -eq '<=')  {
            $_.Action = 'New IP, adding to firewall'
        } 
          
        $_
    }
    if ($script:comp.Count -ge 1) {
        $script:comp | Add-Member -Name "Time" -MemberType NoteProperty -Value "$(Get-Date -Format "dd/MM/yy HH:mm:ss")" | Out-Null
        }
    sleep -Milliseconds 300
    }
# End Functions
sleep -Seconds 2
# Start Loooooooop 
While (1) {
    get_log_ips
    if ($fwav -eq $true) { 
        get_fw_ips
        $fwf = $false
        } # if firewall available, get fw-ips
    elseif ($fwav -eq $false -and $lfd_ips.Count -ge 1 -and $lfd_ips[0] -ne "")  {
        $fw_ips = @('')
        compare_ips $lfd_ips $fw_ips
        $host.UI.RawUI.WindowTitle = "PSLFD: Create Rule"
        New-NetFirewallRule -DisplayName "PowerShell Login Failure Daemon" -Name "PSLFD" -Action Block -RemoteAddress $($lfd_ips) -InterfaceType Any -Direction Inbound
        $fwav = $true
        $script:fwf = $true
        } # if firewall not available and lfd returns some content, create rule

    if ($fwav -eq $true -and $fwf -eq $false) {
        compare_ips $lfd_ips $fw_ips
        if ( $lfd_ips[0] -ne "" -and $script:comp.Count -ge 1) {
            "Changed Entries"
            $script:comp
            $host.UI.RawUI.WindowTitle = "PSLFD: Updating Firewall"
            Set-NetFirewallRule -Name "PSLFD" -RemoteAddress $lfd_ips | Out-Null
            } # Firewall available and not created freshly? compare and update if there is content
        }
    elseif ($fwav -eq $true) {
        $fwf = $false
        } # on next loop, run the compare and update
    
    if ($lfd_ips.Count -le 1 -and $lfd_ips[0] -eq "") {
        Remove-NetFirewallRule -Name "PSLFD"
        $fwav = $false
        } # No content in lfd? Remove Firewall (keep it clean)
    $host.UI.RawUI.WindowTitle = "PSLFD: Idle"
    sleep -Seconds $sleeptime
    }
# No Loop End. It will never STOP!
# Kill it with CTRL+C