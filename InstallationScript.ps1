# https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
# Application Verifier for Windows
# Windows App Certification Kit 

# Set-ExecutionPolicy RemoteSigned
# Set-ExecutionPolicy Restricted

# DEFINE VARIABLES
$EXEC_NAME = "Test.exe"
$FOLDER_PATH = "C:\PresteetoPc_Software_9"
$SRC_PATH = $PSScriptRoot + "\" + $execName
$SUBJECT = "PresteetoPc_LocatorApp"
$PASSWORD = "PresteetoPc_Software20241208"

$rootUser = "PresteetoPc"
$taskName = "PresteetoPcLocatorAppScheduler"
$taskTriggerTime = "10:00"


function Create-PresteetoPc_SoftwareFolder {
    param (
        [string]$FolderPath
    )

    New-Item -ItemType Directory -Path $FolderPath -Force | Out-Null
}


function Sign-LocatorAppExecutable {
    param(
        [string]$ExecName,
        [string]$Password,
        [string]$CertFileName,
        [string]$Subject,
        [string]$CertLocation
    )

    $signToolPath = Join-Path -Path $PSScriptRoot -ChildPath "signtool.exe"
    if (Test-Path $signToolPath) {
        $cert = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation $CertLocation -Type CodeSigningCert
        $pwd = ConvertTo-SecureString -String $Password -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath $CertFileName -Password $pwd    
        try {
            Start-Process -FilePath $signToolPath -ArgumentList "sign /f ${CertFileName} /fd sha1 /p ${Password} $ExecName"
        }
        catch {
            Write-Error "Failed to sign executable please contact developer"
            exit 1
        }
    } else {
        Write-Error "signtool.exe needs to be in the same directory as powershell script root"
        exit 1
    }
}


function Copy-ExecutableToSecureFolder {
    param (
        [string]$CurrentExecPath,
        [string]$FolderPath,
        [string]$ExecName
    )

    try {
        if (Test-Path $CurrentExecPath) {
            Copy-Item -Path $CurrentExecPath -Destination $FolderPath -Force
            Write-Host "Copy $CurrentExecPath to ${FolderPath}"

            $copiedExecPath = Join-Path $FolderPath $ExecName
            $execAcl = Get-Acl $copiedExecPath
            $execAcl.SetAccessRuleProtection($false, $true)
            Set-Acl -Path $copiedExecPath -AclObject $execAcl

            Write-Host "Permissions for $ExecName have been reset to inherit from the folder"
        } else {
            Write-Error "Executable not found at $CurrentExecPath"
            exit 1
        }
    }
    catch {
        Write-Error "Error in Move-ExecutableToSecureFolder"
        exit 1
    }
}


function Update-FolderPermissions {
    param (
        [string]$ContentPath
    )

    try {
        # Get permissions
        $acl = Get-Acl $ContentPath

        # Remove inherited permissions
        $acl.SetAccessRuleProtection($true, $false)
    
        # Remove all existing permissions
        Write-Host "$acl.Access"
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

        # Get the current user's name
        $currentUser = (Get-WmiObject -Class Win32_ComputerSystem).Username.Split('\')[-1]
        Write-Host "Current user: $currentUser"

        # Define an array of access rules
        $accessRules = @(
            New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
            New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
            New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
            New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
            New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "Delete", "ContainerInherit,ObjectInherit", "None", "Deny")
            New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Deny")
            New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "Delete", "ContainerInherit,ObjectInherit", "None", "Deny")
            New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Deny")
            New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "Delete", "ContainerInherit,ObjectInherit", "None", "Deny")
            New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Deny")
        )

        # Apply access rules
        foreach ($rule in $accessRules) {
            Write-Host "$rule"
            $acl.AddAccessRule($rule)
            Write-Host "-------------------"
        }

        # Set the new ACL
        Set-Acl -Path $ContentPath -AclObject $acl
        Write-Host "Set permissions: ${ContentPath}"
    } 
    catch {
        Write-Error "Error Message: $($_.Exeception.Message)"
        Write-Error "Stack Trace: $($_.Exeception.StackTrace)"
        exit 1
    }
}


function Add-WindowsDefenderExclusion {
    param (
        [string]$FolderPath
    )

    try {
        $exclusions = Get-MpPreference
        if ($exclusions.ExclusionPath -notcontains $FolderPath) {
            Add-MpPreference -ExclusionPath $FolderPath
            Write-Host "Added Windows Defender exclusion for folder: $FolderPath"
        } else {
            Write-Host "Windows Defender exclusion for folder already exists"
        }
    }
    catch {
        Write-Error "Error in Add-WindowsDefenderExclusion"
        exit 1
    }
}


function Install-LocatorApp {
    $execFullPath = Join-Path -Path $FOLDER_PATH -ChildPath $EXEC_NAME

    # Step 1) Create Folder
    Create-PresteetoPc_SoftwareFolder -FolderPath $FOLDER_PATH

    # Step 2) Copy Executable
    Copy-ExecutableToSecureFolder -CurrentExecPath $SRC_PATH -FolderPath $FOLDER_PATH -ExecName $EXEC_NAME 

    # Step 3) Update Folder Permissions
    Update-FolderPermissions -ContentPath $FOLDER_PATH

    # Step 4) Sign The Executable
    Sign-LocatorAppExecutable -ExecName $EXEC_NAME -CertFileName "PresteetoPc.pfx" -Subject $SUBJECT -CertLocation $PSScriptRoot -Password $PASSWORD

    # Step 5) Add Executable To Windows Defender
    Add-WindowsDefenderExclusion -FolderPath $execFullPath
}


Install-LocatorApp
