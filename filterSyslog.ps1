#Function to get matches using regex
function Get-Matches {
  param(
    [Parameter(Mandatory=$true)]
    $Pattern,
   
    [Parameter(ValueFromPipeline=$true)]
    $InputObject
  )
 
 begin {
 
    try {
   $regex = New-Object Regex($pattern)
  }
  catch {
   Throw "Get-Matches: Pattern not correct. '$Pattern' is no valid regular expression."
  }
  $groups = @($regex.GetGroupNames() |
  Where-Object { ($_ -as [Int32]) -eq $null } |
  ForEach-Object { $_.toString() })
 }

 process {
  foreach ($line in $InputObject) {
   foreach ($match in ($regex.Matches($line))) {
    if ($groups.Count -eq 0) {
     ([Object[]]$match.Groups)[-1].Value
    } else {
     $rv = 1 | Select-Object -Property $groups
     $groups | ForEach-Object {
      $rv.$_ = $match.Groups[$_].Value
     }
     $rv
    }
   }
  }
 }
}

#input file
$text = Get-Content "syslog.txt" -Encoding UTF8 -ReadCount 0
#Creates an empty array to store the objects
$colEvents = @()
#Gets the matching entries
$RAW = $text | Get-Matches '(?<date>\w{3}\s\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4}).*?\s(?<loghost>\S\d{3}\S\d{3}).*?\s(?<exttime>\w{3}\s\d?\d\s\d{2}:\d{2}:\d{2}\.\d{3}\s\w{4}).*?\s(?<msgtype>\%\w+\S\d\S\w+).*?\s(?<msg>\w+\s\w+).*?\s\S\w+:\s(?<user>\w+).*?\S\s\S\w+:\s(?<source>\d+.\d+.\d+.\d+).*?\S\s\S\w+:\s(?<localport>\d+)'
#Creating a date time filter
$startdate = [datetime]::parse('2016-04-20 12:15') # Could be set to the time of 30 minutes back from now - [datetime]::Now
$enddate = [datetime]::parse('2016-04-20 14:15') # Could be set to now - [datetime]::Now.AddMinutes(-10)
#Set prev status
$failcount = 0
$breach = $null
$prev_status = $null
#DC IP address
$dc_ip = '192.168.1.5' | Get-Matches '\d+.\d+.\d+' #omit IP addresses from local domain.
#Processing data
$RAW | %{ 
    #We need a Date property that is the datetime type
    $_ | Add-Member -type noteproperty -Name LogDate -Value $([datetime]::ParseExact($_.date.ToString(),"ddd MMM dd HH:mm:ss yyyy",$null))
    If ($_.Logdate -ge $startdate -and $_.Logdate -le $enddate) {
    #Create a new object and store the properties we care about    
    $Err = New-Object PSObject
    $Err | Add-Member -type noteproperty -Name Date -Value $_.LogDate
    $Err | Add-Member -type noteproperty -Name LogHost -Value $_.logHost
    $Err | Add-Member -type noteproperty -Name ExtTime -Value $_.exttime
    $Err | Add-Member -type noteproperty -Name Msgtype -Value $_.msgtype
    $Err | Add-Member -type noteproperty -Name Msg -Value $_.msg
    $Err | Add-Member -type noteproperty -Name User -Value $_.user
    $Err | Add-Member -type noteproperty -Name SourceIP -Value $_.source
    $Err | Add-Member -type noteproperty -Name InitPort -Value $_.localport

    #Login Status
    If ($Err.Msg -like "*Login failed*") {$Status = $false}
    If ($Err.Msg -like "*Login Success*") {$Status = $true}

    #For checking Breach, we need to omit local IP addresses
    if($Err.SourceIP -notmatch $dc_ip){ #The input IP address three octets from n-able
        #Checking on previous and current status to identify breach
        If($prev_status -ne $null){
            if($prev_status -ne $Status){
                #status changed - if failed to success on the same IP, notify it.
                if(($prev_status -eq $false) -and ($failcount -gt 5)){
                    #Breach!
                    $breach = "Yes"
                    $failcount = 0
                    #Possibly set an output value to alarm?
                    Write-Host "Network Breach Alert at: " $_.loghost "from IP address: " $_.source "on port: " $_.localport "at: " $_.date "with using username: " $_.user
                }else{  $breach = $null  }
            }else{ 
                if($Status -eq $false){  $failcount++ } 
                $breach = $null  
            }
            $prev_status = $Status
        }else{
            $breach = $null
            $prev_status = $Status
            if($Status -eq $false){  $failcount++ } 
        }
    }

    $Err | Add-Member -type noteproperty -name Breach -Value $breach
    $Err | Add-Member -type noteproperty -name Count -Value $failcount

    #Add object to the array
    $colEvents += $Err

    #Debug
    #Write-Host $_.date + $_.loghost + $_.exttime + $_.msgtype + $_.msg + $_.user + $_.source + $_.localport
    } 
}

#Create output files
$colEvents | Sort-Object -Property LogHost,Date | Format-Table -GroupBy User -Property Date,User,Msg, SourceIP, InitPort, Count, Breach | Out-File ActivitybyUser.txt
