<#PSScriptInfo

.VERSION 1.0.0

.GUID 62213230-4366-43d6-a931-7c41be64e562


.COPYRIGHT 

.TAGS 

.LICENSEURI 

.PROJECTURI http://gitlab/corp/Security.git

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


#>

Function Get-SrvSysVersion{
<#
	.SYNOPSIS
		Check WannaCrypt Exposure

	.DESCRIPTION
		

	.EXAMPLE
        Get-SrvSysVersion
        Defaults to localhost


	.NOTES
		Based on https://support.microsoft.com/en-us/help/4023262/how-to-verify-that-ms17-010-is-installed
#>
[CmdletBinding(
    DefaultParameterSetName = "ByComputerName"
)]
[OutputType(
    [PSCustomObject]
)]

param (
    [Parameter(
        ParameterSetName = "ByComputerName",
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true
    )]
    [ValidateScript({
        if (Test-Connection -ComputerName $_ -Count 1 -Quiet) {
            return $true
        } else {
            throw "Failed to contact '$_'."
        }
    })]
    [Alias(
        "ComputerName"    
    )]
    [String[]]
    $Name = $env:COMPUTERNAME,

    [Parameter(
        ParameterSetName = "ByComputerName"
    )]
    [System.Management.Automation.PSCredential]
    $Credential = [PSCredential]::Empty
)

Begin{
$s = "%systemroot%\system32\drivers\srv.sys"
$v = [System.Environment]::ExpandEnvironmentVariables($s)
$share = $v -replace ":","$"

If ($Name -ne $env:COMPUTERNAME){
    $PATH = "\\$NAME\$share"
}
Else{$PATH = $v}
}

Process{
    Write-Verbose "Checking $PATH exists"
    If (Test-Path $PATH){
        Write-Verbose "$PATH found"
        Try
            {
            $versionInfo = (Get-Item $v).VersionInfo
            $versionString = "$($versionInfo.FileMajorPart).$($versionInfo.FileMinorPart).$($versionInfo.FileBuildPart).$($versionInfo.FilePrivatePart)"
            $fileVersion = New-Object System.Version($versionString)
            return $fileVersion}
        Catch{
            Write-Verbose "Unable to retrieve file version info, please verify vulnerability state manually"
            Return }
        }
    Else{Write-Verbose "$PATH not found"}
}

End{}
}
