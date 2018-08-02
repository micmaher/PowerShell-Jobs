#region Variables
    $kScript = 'hotfixCheck'
    $Kdate = (Get-Date).ToString('yyyy-MM-dd_H-mm')
    $kSQLSERVER = 'MSSQLSRV'      
    $kLastUpdateTable = 'dbo.genericLastUpdated'
    $kDBName = 'Reports'
    $kSchema = 'dbo'
    $kTableHotfix = 'serverInventoryHotfix'
    $kTableHostname = 'serverInventoryHostname'
    $klogRoot = 'E:\Scripts\Logs'
    $kCarbonserver = 'grafana.corp.com'
    $kCarbonport = '2015'
#endregion

. 'C:\Program Files\WindowsPowerShell\Scripts\Get-SrvSysVersion.ps1'

#region Logging
    if(!(Test-Path -Path "$klogRoot\$Kscript" )){
        New-Item -ItemType directory -Path "$klogRoot\$Kscript"
    }
    Start-Transcript -Path "$klogRoot\$Kscript\$Kdate-$kScript.log"
#endregion

filter ConvertTo-StringifiedProperties {
  $ohtOut = [ordered] @{}
  foreach ($propName in (Get-Member -InputObject $_ -Type Properties).Name) {
    $propValue = $_.$propName
    # Note: Properties containing an empty string are treated as NULLs.
    #       To change this behavior, remove the  `-or '' -eq $propValue` part.
    if ($null -eq $propValue -or '' -eq $propValue) { 
      $propValueText = 'NULL' 
    } 
    else {
      $propValueText = "'" + ($propValue -replace "'", "''") + "'"
    } 

    $ohtOut.Add($propName, $propValueText)
  }
  [PSCustomObject] $ohtOut
}


#region Get Firewall State
#$fwState = Foreach ($c in $com){
#Get-FirewallState -Hostname $c.hostname 
#}
#endregion

#region Get Patch State

Get-Job | Remove-Job -Force

$com = Invoke-Sqlcmd -Query "Select Hostname from $kDBName.$kSchema.$kTableHostname" -ServerInstance $kSQLSERVER | Select -ExpandProperty Hostname
$com = $com | select -First 5

# Counters and settings
$throttle = 20
$jobs = @()
$count = 0

# Invoke the jobs.
while ($count -lt $com.Count) {
    if ((Get-Job -State Running).Count -lt $throttle) {
        $jobs += Start-Job -ScriptBlock { try {Get-SrvSysVersion -Name $args[0] -Verbose -ErrorAction Stop } catch { throw $_ } } -Name $com[$count] -ArgumentList @($com[$count])     
        #Write-Progress -Activity "Testing for WannaCry vulnerability accross $($com.Count) systems" -Status "Invoked on $($com[$count].ToString())" -PercentComplete ($jobs.Count / $com.Count * 100)
        
        $count++
    }
}
#Write-Progress -Activity "Testing for WannaCry vulnerability accross $($com.Count) systems" -Completed

# Wait for remaining jobs to finish.
while (($jobsRemaining = (Get-Job -State Running).Count) -ne 0) {
    Write-Progress -Activity "Waiting for remaining jobs to finish" -Status "$jobsRemaining jobs remaining"
}
#Write-Progress -Activity "Waiting for remaining jobs to finish" -Completed

foreach ($completedJob in (Get-Job -State Completed)) {
    $receivedJob = Receive-Job -Job $completedJob

    $oRes = [PSCustomObject]@{
        Hostname = $completedJob.name
        Major = $receivedJob.Major
        Minor = $receivedJob.Minor
        Build = $receivedJob.Build
        Revision = $receivedJob.Revision
    } | ConvertTo-StringifiedProperties

    #Write-Verbose $completedOutput 

    Write-Verbose "Flushing $kDBName.$kSchema.$kTableHotfix"
    
    Invoke-Sqlcmd -Query "delete from $kDBName.$kSchema.$kTableHotfix Where hostname = $($oRes.Hostname)" -ServerInstance $kSQLSERVER 
    #Write-Verbose "Injecting new values for $($ores.Hostname) into $kDBName.$kSchema.$kTableHotfix"

    # Shortcut to create the table
    #Write-SqlTableData -ServerInstance $kSQLServer -DatabaseName $kDBName -SchemaName $kSchema -TableName $kTableHotfix -InputData $oRes -Verbose -force
    
    Write-Verbose $oRes
    Invoke-Sqlcmd -Query "INSERT into $kTableHotfix (Hostname, Vulnerable, AppliedHotfixID, SMB1FeatureEnabled, SMB1ProtocolEnabled) VALUES ($($oRes.hostname), $($oRes.Vulnerable), $($oRes.AppliedHotfixID), $($oRes.SMB1FeatureEnabled), $($oRes.SMB1ProtocolEnabled))" -Database $kDBName -ServerInstance $kSQLSERVER

    Remove-Job -Job $completedJob
}

foreach ($failedJob in (Get-Job -State Failed)) {
    $failedOutput = [PSCustomObject]@{
        Name = $failedJob.Name
    }

    Write-Verbose $failedOutput
    Remove-Job -Job $failedJob
}
Write-Verbose "Inject lastupdated timestamp to SQL"
$exists = Invoke-Sqlcmd -Query "SELECT * from $kLastUpdateTable WHERE recordname = '$($kTableHotfix)';" -Database $kDBName -ServerInstance $kSQLSERVER
If ($exists){Invoke-Sqlcmd -Query "UPDATE $kLastUpdateTable SET lastupdated = (GetDate()), recordname = '$($kTableHotfix)' WHERE recordname = '$($kTableHotfix)';" -Database $kDBName -ServerInstance $kSQLSERVER}
Else {Invoke-Sqlcmd -Query "INSERT INTO $kLastUpdateTable (lastupdated, recordname) VALUES ((GetDate()), '$($kTableHotfix)');" -Database $kDBName -ServerInstance $kSQLSERVER}
#endregion

Stop-Transcript
