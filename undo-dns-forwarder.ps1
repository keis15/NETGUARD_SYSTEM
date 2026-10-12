# Removes the firewall rules added by setup-dns-forwarder.ps1.
# Before running this, set your router's DHCP DNS back to automatic, or devices will lose internet.
# (The Wi-Fi profile is left as Private; change it in Windows Settings if you want Public again.)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# The WiFiMon names are from before the rename to NetGuard.
foreach ($name in 'NetGuard DNS (UDP)', 'NetGuard DNS (TCP)', 'WiFiMon DNS (UDP)', 'WiFiMon DNS (TCP)') {
    Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    Write-Host "Removed: $name"
}
Read-Host "Press Enter to close"
