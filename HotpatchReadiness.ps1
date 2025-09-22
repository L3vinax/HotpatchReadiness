# This script checks a server for readiness to enable hotpatching.
# Certain parts of this script require administrator permissions to run. This will attempt to restart the script with elevated permissions if it is not alredy running as admin.

$global:scriptPath = $myinvocation.mycommand.definition

function Restart-AsAdmin {
    $pwshCommand = "powershell"
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $pwshCommand = "pwsh"
    }

    try {
        Write-Host "This script requires administrator permissions to check for SecureBoot. Attempting to restart script with elevated permissions..."
        $arguments = "-NoExit -Command `"& '$scriptPath'`""
        Start-Process $pwshCommand -Verb runAs -ArgumentList $arguments
        exit 0
    } catch {
        throw "Failed to elevate permissions. Please run this script as Administrator."
    }
}


    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ([System.Environment]::UserInteractive) {
            Restart-AsAdmin
        } else {
            throw "This script requires administrator permissions to check for SecureBoot. Please run this script as Administrator."
        }
}

# This function will check to see if the server is running Windows Server 2025.
function Test-OS {
    $os = get-ciminstance -classname Win32_OperatingSystem
    $build = [int]($os.BuildNumber)
    $hotpatchSKU = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID -eq "ServerTurbine"
    if (($os.Caption -like "*Windows Server 2025*") -or ($os.Caption -like "*Windows Server 2022*" -and $build -ge 20348 -and $hotpatchSKU)) {
        Write-Host "OS: Supported OS Version" -ForegroundColor "Green"
    } else {
        Write-Host "OS: Not Supported Windows Version" -ForegroundColor "Red"
    }
}

# This function will check to see if Virtualization Based Security (VBS) is enabled.
# VBS is a requirement for hotpatching.
function Test-VBS {
    $vbsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $enabled = (Get-ItemProperty -Path $vbsRegPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
    if ($enabled -eq 1) {
        Write-Host "VBS: Enabled (via registry)" -ForegroundColor "Green"
    } else {
        Write-Host "VBS: Not Enabled (via registry)" -ForegroundColor "Red"   
    }
}

# This function will check to see if UEFI and Secure Boot are enabled.
# UEFI and Secure Boot are requirements for hotpatching.
# This specific part requires administrator permissions to run.
function Test-UEFISecureBoot {
    $firmware = get-ciminstance -classname Win32_BIOS
    if ($firmware.SMBIOSBIOSVersion -like "*VMW71*" -or $firmware.SMBIOSBIOSVersion -like "*UEFI*") {
        $secureboot = Confirm-SecureBootUEFI
        if ($secureboot) {
        Write-Host "UEFI: Enabled" -ForegroundColor "Green"
        Write-Host "Secure Boot: Enabled" -ForegroundColor "Green"
    } else {
        Write-Host "UEFI: Enabled" -ForegroundColor "Green"
        Write-Host "Secure Boot: Not Enabled" -ForegroundColor "Red"
    }
    } else {
        Write-Host "UEFI: Not Enabled" -ForegroundColor "Red"
        Write-Host "Secure Boot: Not Applicable" -ForegroundColor "Red"
    }
}

# This function will check to see if the OS version is running a compatible build for hotpatching.
function Test-HotpatchBaseline {
    $os = get-ciminstance -classname Win32_OperatingSystem
    if ($os.BuildNumber -ge 26100) {
        Write-Host "Hotpatch Baseline: Supported" -ForegroundColor "Green"
    } else {
        Write-Host "Hotpatch Baseline: Not Supported" -ForegroundColor "Red"
    }
}

Test-OS
Test-VBS
Test-UEFISecureBoot
Test-HotpatchBaseline
