# Define the list of browser executables to allow
$allowedBrowsers = @("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe")

# Function to add firewall rules
function Add-FirewallRules {
    Write-Host "Setting up firewall rules..."

    # Block all outbound traffic by default
    Write-Host "Blocking all outbound traffic..."
    New-NetFirewallRule -DisplayName "Block All Outbound Traffic" -Direction Outbound -Action Block -Profile Any

    # Allow traffic for each browser
    foreach ($browser in $allowedBrowsers) {
        Write-Host "Allowing outbound traffic for $browser..."
        New-NetFirewallRule -DisplayName "Allow $browser" -Direction Outbound -Action Allow -Program "C:\Program Files (x86)\$browser" -Profile Any -Enabled True
    }
	
	# Allow DHCP traffic (ports 67 and 68)
	Write-Host "Allowing DHCP traffic on ports 67 and 68..."
	New-NetFirewallRule -DisplayName "Allow DHCP Server" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 67 -Profile Any
	New-NetFirewallRule -DisplayName "Allow DHCP Client" -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -Profile Any
	
    # Allow DNS (port 53) for resolving domain names
    Write-Host "Allowing DNS traffic..."
    New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound -Action Allow -Protocol UDP -LocalPort 53 -Profile Any
    New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound -Action Allow -Protocol TCP -LocalPort 53 -Profile Any

    # Allow HTTP and HTTPS traffic (ports 80 and 443)
    Write-Host "Allowing HTTP and HTTPS traffic..."
    New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Outbound -Action Allow -Protocol TCP -LocalPort 80 -Profile Any
    New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Outbound -Action Allow -Protocol TCP -LocalPort 443 -Profile Any
}

# Function to reset firewall rules
function Reset-FirewallRules {
    Write-Host "Resetting firewall rules to default..."
    netsh advfirewall reset
}

# Main menu
Write-Host "1. Restrict network traffic to browsers"
Write-Host "2. Reset firewall rules to default"
$choice = Read-Host "Enter your choice (1 or 2)"

switch ($choice) {
    "1" {
        Add-FirewallRules
    }
    "2" {
        Reset-FirewallRules
    }
    default {
        Write-Host "Invalid choice. Exiting..."
    }
}
