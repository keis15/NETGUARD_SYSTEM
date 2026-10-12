# One-time Windows setup so other devices on your Wi-Fi can use NetGuard's DNS forwarder.
# Right-click > "Run with PowerShell" (it asks for Administrator rights).
#   1. Allows inbound DNS (UDP+TCP 53) in Windows Firewall, on Private networks only
#   2. Sets the current Wi-Fi network profile to Private
# Undo with undo-dns-forwarder.ps1

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$ErrorActionPreference = 'Stop'
try {
    foreach ($proto in 'UDP', 'TCP') {
        $name = "NetGuard DNS ($proto)"
        if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol $proto `
                -LocalPort 53 -Profile Private | Out-Null
            Write-Host "Added firewall rule: $name" -ForegroundColor Green
        } else {
            Write-Host "Firewall rule already exists: $name"
        }
    }

    $wifi = Get-NetConnectionProfile | Where-Object {
        (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).PhysicalMediaType -eq 'Native 802.11'
    }
    foreach ($p in $wifi) {
        if ($p.NetworkCategory -ne 'Private') {
            Set-NetConnectionProfile -InterfaceIndex $p.InterfaceIndex -NetworkCategory Private
            Write-Host "Wi-Fi '$($p.Name)' set to Private" -ForegroundColor Green
        } else {
            Write-Host "Wi-Fi '$($p.Name)' is already Private"
        }
    }

    $ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $wifi[0].InterfaceIndex).IPAddress
    Write-Host ""
    Write-Host "Done. Next, in your router's admin page set the DHCP Primary DNS to: $ip" -ForegroundColor Cyan
    Write-Host "and reserve $ip for this PC. Then reconnect your devices to Wi-Fi."
} catch {
    Write-Host "Failed: $_" -ForegroundColor Red
}
Read-Host "Press Enter to close"
