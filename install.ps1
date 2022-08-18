Write-Host 'creating kptnhook directories @ C:\kptnhook if not exists'
md -Force 'C:\kptnhook'
md -Force 'C:\kptnhook\Ship'
md -Force 'C:\kptnhook\Data'

function allow-dir {
    param ([string]$path, [string]$ident)

    #$user = [Security.Principal.NTAccount]::new($ident).Translate([System.Security.Principal.SecurityIdentifier])
    $user = [Security.Principal.NTAccount]::new("ALL RESTRICTED APPLICATION PACKAGES").Translate([System.Security.Principal.SecurityIdentifier])
    Write-Host $user
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($user, "ReadAndExecute", "Allow")
    $acl = Get-Acl $path
    $acl.SetAccessRule($rule)
    Set-Acl -Path $path -AclObject $acl
}

foreach($path in Get-ChildItem 'C:\kptnhook') {
    allow-dir $path 'ALL RESTRICTED APPLICATION PACKAGES'
    # allow-dir $path 'EVERYONE'
}

$NewAcl = Get-Acl -Path 'C:\kptnhook'
# Set properties
$identity = "BUILTIN\Everyone"
$fileSystemRights = "Read"
$type = "Allow"
# Create new rule
$fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $type
$fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
# Apply new rule
$NewAcl.SetAccessRule($fileSystemAccessRule)
Set-Acl -Path 'C:\kptnhook' -AclObject $NewAcl