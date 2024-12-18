function Create-SecuredProtectedFolder {
    try {
        # Create the folder
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Write-Host "Created folder: $folder"

        # Set permissions
        $acl = Get-Acl $folder

        # Remove inherited permissions
        $acl.SetAccessRuleProtection($true, $false)

        # Remove all existing permissions
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

        # Get the current user's name
        $currentUser = (Get-WmiObject -Class Win32_ComputerSystem).Username.Split('\')[-1]
        Write-Host "Current user: $currentUser"

        # Define an array of access rules
        $accessRules = @(
            New-Object System.Security.AccessControl.FileSystemAccessRule("$currentUser", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")
            New-Object System.Security.AccessControl.FileSystemAccessRule("$presteetoUser", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        )

        # Apply access rules
        foreach ($rule in $accessRules) {
            $acl.AddAccessRule($rule)
        }

        # Set the new ACL
        Set-Acl -Path $folder -AclObject $acl
        Write-Host "Set permissions for folder: $folder"
    }
    catch {
        Write-Error "Error in Create-SecuredProtectedFolder: $_"
        exit 1
    }
}
