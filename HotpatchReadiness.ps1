function Test-OS {
    $os = get-ciminstance -classname Win32_OperatingSystem
    if ($os.Caption -like "*Windows Server 2025*") {
        Write-Host "OS: Windows Server 2025" -ForegroundColor "Green"
    } else {
        Write-Host "OS: Not Windows Server 2025" -ForegroundColor "Red"
}
}

function Test-VBS {
    $vbsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $enabled = (Get-ItemProperty -Path $vbsRegPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
    if ($enabled -eq 1) {
        Write-Host "VBS: Enabled (via registry)" -ForegroundColor "Green"
    } else {
        Write-Host "VBS: Not Enabled (via registry)" -ForegroundColor "Red"   
    }
}

function Test-UEFI-SecureBoot {
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
Test-UEFI-SecureBoot
Test-HotpatchBaseline
