# v1.1.3.12

function Add-TrueTypeFont {
    <#
    .SYNOPSIS
    Adds TTF files to Windows.
    .DESCRIPTION
    Adds TTF files to Windows Control Panel on the local computer only. Must run as admin.
    .EXAMPLE
    dir \\server\share\fonts\*.ttf | Add-TrueTypeFont
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true,
                    Position=0)]
        [ValidatePattern('.+\.ttf$')]
        [Alias('FilePath','FullName')]
        [string[]]
        $Path
    )
    
    begin {
        
        # Namespace ID
        $FONTS = 0x14
        
        Set-Variable -Name ErrorActionPreference -Scope Script -Value 'Stop'

        Try {

            $objShell = New-Object -ComObject Shell.Application

        } Catch {
            
            throw "Missing COMObject: Shell.Application"

        }

        Try {
            
            $objFolder = $objShell.Namespace($FONTS)
            
        } Catch {
            
            throw "Unable to load Font Namespace:`n$($_.Exception.Message)"
            
        }
        
        Set-Variable -Name ErrorActionPreference -Scope Script -Value 'SilentlyContinue'
        
    }
    
    process {

        Foreach ($p in $Path) {

            $objFile = Get-Item $p
            $FontName = $objFile.name
            if (Test-Path "c:\windows\fonts\$FontName") {

                Write-Verbose "Font already installed: $($FontName)"

            } else {

                if (Test-Path $objFile.FullName) {

                    $CopyOptions = 4 + 16; # from https://www.reddit.com/r/sysadmin/comments/a64lax/windows_1809_breaks_powershell_script_to_install/ebs68wj?utm_source=share&utm_medium=web2x
                    [void]($ObjFolder.CopyHere($objFile.fullname, $CopyOptions));
                    $regPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts"
                    New-ItemProperty -Name $objFile.fullname -Path $regPath -PropertyType string -Value ($objFile.fullname)
                    
                    # Test each action
                    $Installed = Get-Font $FontName
                    if ($Installed) {
                        Write-Verbose "Font successfully installed: $($FontName)"
                    } else {
                        Write-Warning "Font not installed: $($FontName)!"
                    }

                } else {
        
                    Write-Warning "Path not found: $($objFile.fullname)"
                
                }

            }

        }

    }
    
    end {

        if ($Error) {

            $Error | ForEach-Object { Write-Verbose $_.Exception.Message }

        }

    }

}

function Get-Font {      
    <#
    .Synopsis
        Gets the fonts currently loaded on the system
    .Description
        Uses the type System.Windows.Media.Fonts static property SystemFontFamilies,
        to retrieve all of the fonts loaded by the system.  If the Fonts type is not found,
        the PresentationCore assembly will be automatically loaded
    .Parameter Font
        A string supporting wildcards to search for font names
    .Example
        # Get All Fonts
        Get-Font
    .Example
        # Get All Lucida Fonts
        Get-Font *Lucida*
    .Notes
    https://blogs.msdn.microsoft.com/mediaandmicrocode/2008/12/24/microcode-powershell-scripting-tricks-get-font/
    #>
    param(
        $Font = "*"
    )

    if (-not ("Windows.Media.Fonts" -as [Type])) {
        Add-Type -AssemblyName "PresentationCore"
    }       

    [Windows.Media.Fonts]::SystemFontFamilies |
        Where-Object { $_.Source -like "$font" } 

}

function Get-Font {      
    <#
    .Synopsis
        Gets the fonts currently loaded on the system
    .Description
        Uses the type System.Windows.Media.Fonts static property SystemFontFamilies,
        to retrieve all of the fonts loaded by the system.  If the Fonts type is not found,
        the PresentationCore assembly will be automatically loaded
    .Parameter Font
        A string supporting wildcards to search for font names
    .Example
        # Get All Fonts
        Get-Font
    .Example
        # Get All Lucida Fonts
        Get-Font *Lucida*
    .Notes
    https://blogs.msdn.microsoft.com/mediaandmicrocode/2008/12/24/microcode-powershell-scripting-tricks-get-font/
    #>
    param(
        $Font = "*"
    )

    if (-not ("Windows.Media.Fonts" -as [Type])) {
        Add-Type -AssemblyName "PresentationCore"
    }       

    [Windows.Media.Fonts]::SystemFontFamilies |
        Where-Object { $_.Source -like "$font" } 

}

function Get-PathFolders
{
    $env:Path -split ';' | 
        foreach -Process {
            if ( -not [string]::IsNullOrEmpty($_) ) {        
                $_.trimend('\\')
            }
        }
}

function Receive-PsExec 
{
    [CmdletBinding()]
    Param
    (
        # Where to grab the file from
        [string]
        $SourceUri = 'https://automate.rfa.com/rfadl/PsExec.exe',

        # Where to download the file to
        [string]
        $TargetDir = $env:windir,

        # Force overwite existing file
        [switch]$Force
    )
    Begin
    {
        $WebClient = new-object System.Net.WebClient
        $Paths = Get-PathFolders
        $FoundHere = @()
        $Paths | foreach -Process {
            if (
                Test-Path (Join-Path $_ 'psexec.exe')
            )
            {
                $FoundHere += (Join-Path $_ 'psexec.exe')
            }
        }
        $PsExecExists = $FoundHere.Count -gt 0
    }
    Process {}
    End
    {
        # Abort if found in a path location. 
        if( -not $PsExecExists -or $Force)
        {
            # Download the file into its target location
            Try {
                $WebClient.DownloadFile($SourceUri,$TargetDir)
            } Catch {
                throw "File download failed.`n$($_.Exception)"
            }
            
            # Check to see if it worked 
            if (Test-Path $TargetDir) {
                Write-Verbose "File Downloaded OK"
            } else { 
                Write-Warning "File Download Failed!"
            }
        }
    }
}

function Get-RebootReport {
    [CmdletBinding()]
    param (
        # Computer(s) to report on reboot history.
        [Parameter(Position=0)]
        [string[]]
        $ComputerName=$env:COMPUTERNAME
    )
    
    begin {
    }
    
    process {
        foreach ($Computer in $ComputerName) {
            if ( ( Test-Connection $Computer -Count 1 -ea 0 ) -eq $null ){
                Write-Warning "The device named $Computer is not responding to an Echo request!"
            }else{
        
            Get-WinEvent -ComputerName $Computer -FilterHashtable @{
                logname='System'; id=1074} |
                    ForEach-Object {
                        $rv = New-Object PSObject |
                            Select-Object Date,
                                        User,
                                        Action,
                                        Process,
                                        Reason,
                                        ReasonCode,
                                        Comment
                        $rv.Date = $_.TimeCreated
                        $rv.User = $_.Properties[6].Value
                        $rv.Process = $_.Properties[0].Value -replace '^.*\\' -replace '\s.*$'
                        $rv.Action = $_.Properties[4].Value
                        $rv.Reason = $_.Properties[2].Value
                        $rv.ReasonCode = $_.Properties[3].Value
                        $rv.Comment = $_.Properties[5].Value
                        $rv
                    }
            }
        }
    }
    
    end {
    }
}

Function Get-PendingReboot {
    <#
    .SYNOPSIS
        Gets the pending reboot status on a local or remote computer.

    .DESCRIPTION
        This function will query the registry on a local or remote computer and determine if the
        system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer 
        Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the 
        CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations" 
        and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.
        
        CBServicing = Component Based Servicing (Windows 2008+)
        WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
        CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
        PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
        PendFileRename = PendingFileRenameOperations (Windows 2003+)
        PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
                        Virus leverage this key for def/dat removal, giving a false positive PendingReboot

    .PARAMETER ComputerName
        A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

    .PARAMETER ErrorLog
        A single path to send error data to a log file.

    .EXAMPLE
        PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize
        
        Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
        -------- ----------- ------------- ------------ -------------- -------------- -------------
        DC01           False         False                       False                        False
        DC02           False         False                       False                        False
        FS01           False         False                       False                        False

        This example will capture the contents of C:\ServerList.txt and query the pending reboot
        information from the systems contained in the file and display the output in a table. The
        null values are by design, since these systems do not have the SCCM 2012 client installed,
        nor was the PendingFileRenameOperations value populated.

    .EXAMPLE
        PS C:\> Get-PendingReboot
        
        Computer           : WKS01
        CBServicing        : False
        WindowsUpdate      : True
        CCMClient          : False
        PendComputerRename : False
        PendFileRename     : False
        PendFileRenVal     : 
        RebootPending      : True
        
        This example will query the local machine for pending reboot information.
        
    .EXAMPLE
        PS C:\> $Servers = Get-Content C:\Servers.txt
        PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation
        
        This example will create a report that contains pending reboot information.

    .LINK
        Component-Based Servicing:
        http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx
        
        PendingFileRename/Auto Update:
        http://support.microsoft.com/kb/2723674
        http://technet.microsoft.com/en-us/library/cc960241.aspx
        http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

        SCCM 2012/CCM_ClientSDK:
        http://msdn.microsoft.com/en-us/library/jj902723.aspx

    .NOTES
        Author:  Brian Wilhite
        Email:   bcwilhite (at) live.com
        Date:    29AUG2012
        PSVer:   2.0/3.0/4.0/5.0
        Updated: 27JUL2015
        UpdNote: Added Domain Join detection to PendComputerRename, does not detect Workgroup Join/Change
                Fixed Bug where a computer rename was not detected in 2008 R2 and above if a domain join occurred at the same time.
                Fixed Bug where the CBServicing wasn't detected on Windows 10 and/or Windows Server Technical Preview (2016)
                Added CCMClient property - Used with SCCM 2012 Clients only
                Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
                Removed $Data variable from the PSObject - it is not needed
                Bug with the way CCMClientSDK returned null value if it was false
                Removed unneeded variables
                Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
                Removed .Net Registry connection, replaced with WMI StdRegProv
                Added ComputerPendingRename
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias("CN","Computer")]
        [String[]]$ComputerName="$env:COMPUTERNAME",
        [String]$ErrorLog
        )

    Begin {  }## End Begin Script Block
    Process {
    Foreach ($Computer in $ComputerName) {
        Try {
            ## Setting pending values to false to cut down on the number of else statements
            $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
                            
            ## Setting CBSRebootPend to null since not all versions of Windows has this value
            $CBSRebootPend = $null
                            
            ## Querying WMI for build version
            $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

            ## Making registry connection to the local/remote computer
            $HKLM = [UInt32] "0x80000002"
            $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
                            
            ## If Vista/2008 & Above query the CBS Reg Key
            If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
                $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
                $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
            }
                                
            ## Query WUAU from the registry
            $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
            $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
                            
            ## Query PendingFileRenameOperations from the registry
            $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
            $RegValuePFRO = $RegSubKeySM.sValue

            ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
            $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
            $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

            ## Query ComputerName and ActiveComputerName from the registry
            $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")            
            $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")

            If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
                $CompPendRen = $true
            }
                            
            ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
            If ($RegValuePFRO) {
                $PendFileRename = $true
            }

            ## Determine SCCM 2012 Client Reboot Pending Status
            ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
            $CCMClientSDK = $null
            $CCMSplat = @{
                NameSpace='ROOT\ccm\ClientSDK'
                Class='CCM_ClientUtilities'
                Name='DetermineIfRebootPending'
                ComputerName=$Computer
                ErrorAction='Stop'
            }
            ## Try CCMClientSDK
            Try {
                $CCMClientSDK = Invoke-WmiMethod @CCMSplat
            } Catch [System.UnauthorizedAccessException] {
                $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
                If ($CcmStatus.Status -ne 'Running') {
                    Write-Warning "$Computer`: Error - CcmExec service is not running."
                    $CCMClientSDK = $null
                }
            } Catch {
                $CCMClientSDK = $null
            }

            If ($CCMClientSDK) {
                If ($CCMClientSDK.ReturnValue -ne 0) {
                    Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"          
                }
                If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
                    $SCCM = $true
                }
            }
                
            Else {
                $SCCM = $null
            }

            ## Creating Custom PSObject and Select-Object Splat
            $SelectSplat = @{
                Property=(
                    'Computer',
                    'CBServicing',
                    'WindowsUpdate',
                    'CCMClientSDK',
                    'PendComputerRename',
                    'PendFileRename',
                    'PendFileRenVal',
                    'RebootPending'
                )}
            New-Object -TypeName PSObject -Property @{
                Computer=$WMI_OS.CSName
                CBServicing=$CBSRebootPend
                WindowsUpdate=$WUAURebootReq
                CCMClientSDK=$SCCM
                PendComputerRename=$CompPendRen
                PendFileRename=$PendFileRename
                PendFileRenVal=$RegValuePFRO
                RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
            } | Select-Object @SelectSplat

        } Catch {
            Write-Warning "$Computer`: $_"
            ## If $ErrorLog, log the file to a user specified location/path
            If ($ErrorLog) {
                Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
            }				
        }			
    }## End Foreach ($Computer in $ComputerName)			
    }## End Process

    End {  }## End End

}## End Function Get-PendingReboot

function Get-HotfixApiCombo {
    param ()

    $Session = New-Object -ComObject "Microsoft.Update.Session"
    $Searcher = $Session.CreateUpdateSearcher()
    $historyCount = $Searcher.GetTotalHistoryCount()
    $UpdateHistory = $Searcher.QueryHistory(0, $historyCount)
    $KBs = @()
    foreach ($Update in $UpdateHistory) {
                    [regex]::match($Update.Title,'(KB[0-9]{6,7})').value | Where-Object {$_ -ne ""} | foreach {
                        $KB = New-Object -TypeName PSObject
                        $KB | Add-Member -MemberType NoteProperty -Name KB -Value $_
                        $KB | Add-Member -MemberType NoteProperty -Name Title -Value $Update.Title
                        $KB | Add-Member -MemberType NoteProperty -Name Description -Value $Update.Description
                        $KB | Add-Member -MemberType NoteProperty -Name Date -Value $Update.Date
                        $KBs += $KB
                    }
                }

    $result = $KBs | select date,kb

    $hf = Get-Hotfix 

    $Result += $HF |
        where {@($KBs.kb|select -Unique) -notcontains $_.hotfixID} |
        select @{n='date';exp={$_.installedon}}, @{n='kb';exp={$_.hotfixid}}

    $Result | sort date
}

Function Get-InstalledSoftware {
    <#
    .SYNOPSIS
        Get-InstalledSoftware retrieves a list of installed software
    .DESCRIPTION
        Get-InstalledSoftware opens up the specified (remote) registry and scours it for installed software. When found it returns a list of the software and it's version.
    .PARAMETER ComputerName
        The computer from which you want to get a list of installed software. Defaults to the local host.
    .EXAMPLE
        Get-InstalledSoftware DC1
        
        This will return a list of software from DC1. Like:
        Name			Version		Computer  UninstallCommand
        ----			-------     --------  ----------------
        7-Zip 			9.20.00.0	DC1       MsiExec.exe /I{23170F69-40C1-2702-0920-000001000000}
        Google Chrome	65.119.95	DC1       MsiExec.exe /X{6B50D4E7-A873-3102-A1F9-CD5B17976208}
        Opera			12.16		DC1		  "C:\Program Files (x86)\Opera\Opera.exe" /uninstall
    .EXAMPLE
        Import-Module ActiveDirectory
        Get-ADComputer -filter 'name -like "DC*"' | Get-InstalledSoftware
        
        This will get a list of installed software on every AD computer that matches the AD filter (So all computers with names starting with DC)
    .INPUTS
        [string[]]Computername
    .OUTPUTS
        PSObject with properties: Name,Version,Computer,UninstallCommand
    .NOTES
        Copied by Tony Pagliaro (RFA) from: https://community.spiceworks.com/scripts/show_download/2170-get-a-list-of-installed-software-from-a-remote-computer-fast-as-lightning

        Author: Anthony Howell
        
        To add directories, add to the LMkeys (LocalMachine)    
    .LINK
        [Microsoft.Win32.RegistryHive]
        [Microsoft.Win32.RegistryKey]
    #>
    Param(
        [Alias('Computer','ComputerName','HostName')]
        [Parameter(
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$true,
            Position=1
        )]
        [string]$Name = $env:COMPUTERNAME
    )
    Begin{
        $lmKeys = "Software\Microsoft\Windows\CurrentVersion\Uninstall","SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        $lmReg = [Microsoft.Win32.RegistryHive]::LocalMachine
        $cuKeys = "Software\Microsoft\Windows\CurrentVersion\Uninstall"
        $cuReg = [Microsoft.Win32.RegistryHive]::CurrentUser
    }
    Process{
        if (!(Test-Connection -ComputerName $Name -count 1 -quiet)) {
            Write-Error -Message "Unable to contact $Name. Please verify its network connectivity and try again." -Category ObjectNotFound -TargetObject $Computer
            Break
        }
        $masterKeys = @()
        $remoteCURegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($cuReg,$computer)
        $remoteLMRegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($lmReg,$computer)
        foreach ($key in $lmKeys) {
            $regKey = $remoteLMRegKey.OpenSubkey($key)
            foreach ($subName in $regKey.GetSubkeyNames()) {
                foreach($sub in $regKey.OpenSubkey($subName)) {
                    $masterKeys += (New-Object PSObject -Property @{
                        "ComputerName" = $Name
                        "Name" = $sub.getvalue("displayname")
                        "SystemComponent" = $sub.getvalue("systemcomponent")
                        "ParentKeyName" = $sub.getvalue("parentkeyname")
                        "Version" = $sub.getvalue("DisplayVersion")
                        "UninstallCommand" = $sub.getvalue("UninstallString")
                        "InstallDate" = $sub.getvalue("InstallDate")
                        "RegPath" = $sub.ToString()
                    })
                }
            }
        }
        foreach ($key in $cuKeys) {
            $regKey = $remoteCURegKey.OpenSubkey($key)
            if ($regKey -ne $null) {
                foreach ($subName in $regKey.getsubkeynames()) {
                    foreach ($sub in $regKey.opensubkey($subName)) {
                        $masterKeys += (New-Object PSObject -Property @{
                            "ComputerName" = $Name
                            "Name" = $sub.getvalue("displayname")
                            "SystemComponent" = $sub.getvalue("systemcomponent")
                            "ParentKeyName" = $sub.getvalue("parentkeyname")
                            "Version" = $sub.getvalue("DisplayVersion")
                            "UninstallCommand" = $sub.getvalue("UninstallString")
                            "InstallDate" = $sub.getvalue("InstallDate")
                            "RegPath" = $sub.ToString()
                        })
                    }
                }
            }
        }
        $woFilter = {$null -ne $_.name -AND $_.SystemComponent -ne "1" -AND $null -eq $_.ParentKeyName}
        $props = 'Name','Version','ComputerName','Installdate','UninstallCommand','RegPath'
        $masterKeys = ($masterKeys | Where-Object $woFilter | Select-Object $props | Sort-Object Name)
        $masterKeys
    }
    End{}
}

function Set-EnvironmentVariable {
    <#
    .SYNOPSIS
    Add/update environment variable.
    .DESCRIPTION
    Changes the given environment variable to the given value under the given scope (user profile by default).
    .EXAMPLE
    Set-EnvVariable -Name 'MyVariable' -Value 'MyValue' -Scope 'Machine'
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]

    Param(

        [Parameter(Mandatory=$true,
            Position=0)]
        [string]
        $Name,
        
        [Parameter(Position=1)]
        [string]
        $Value,
        
        [Parameter(Position=2)]
        [ValidateSet('Machine', 'User', 'Process')]
        [string]
        $Scope = "User"

    )

    if ($pscmdlet.ShouldProcess("Environment Variable '$Name' under $Scope scope", "Set value to $Value")) {

        [Environment]::SetEnvironmentVariable($Name, $Value, $Scope)
        Write-Verbose "Environment Variable $Name was set to '$Value' under $Scope."
    
    }
    
    if ($Scope -ne 'Process') {
        Write-Warning "Please restart your session to use the new variable."
    }

}

function Install-DotNet35 {
    <# 
    .EXAMPLE
    Install-DotNet35
    .NOTES
    Run this command as a local admin. 
    From https://raw.githubusercontent.com/LabtechConsulting/LabTech-Powershell-Module/master/LabTech.psm1
    #>
	$DotNET = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse -EA 0 | Get-ItemProperty -name Version,Release -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} | Select-Object -ExpandProperty Version -EA 0
	If (-not ($DotNet -like '3.5.*')){
		Write-Output ".NET Framework 3.5 installation needed."
		#Install-WindowsFeature Net-Framework-Core
		$OSVersion = [System.Environment]::OSVersion.Version

		If ([version]$OSVersion -gt [version]'6.2'){
			Try{
				If ( $PSCmdlet.ShouldProcess('NetFx3', 'Enable-WindowsOptionalFeature') ) {
					$Install = Get-WindowsOptionalFeature -Online -FeatureName 'NetFx3'
					If (!($Install.State -eq 'EnablePending')) {
						$Install = Enable-WindowsOptionalFeature -Online -FeatureName 'NetFx3' -All -NoRestart
					}
					If ($Install.RestartNeeded -or $Install.State -eq 'EnablePending') {
						Write-Output ".NET Framework 3.5 installed but a reboot is needed."
					}
				}
			}
			Catch{
				Write-Error "ERROR: Line $(LINENUM): .NET 3.5 install failed." -ErrorAction Continue
				If (!($Force)) { Write-Error ("Line $(LINENUM):",$Install) -ErrorAction Stop }
			}
		}
		ElseIf ([version]$OSVersion -gt [version]'6.1'){
			If ( $PSCmdlet.ShouldProcess("NetFx3", "Add Windows Feature") ) {
				Try {$Result=& "$env:windir\system32\Dism.exe" /English /NoRestart /Online /Enable-Feature /FeatureName:NetFx3 2>''}
				Catch {Write-Output "Error calling Dism.exe."; $Result=$Null}
				Try {$Result=& "$env:windir\system32\Dism.exe" /English /Online /Get-FeatureInfo /FeatureName:NetFx3 2>''}
				Catch {Write-Output "Error calling Dism.exe."; $Result=$Null}
				If ($Result -contains 'State : Enabled'){
					Write-Warning "WARNING: Line $(LINENUM): .Net Framework 3.5 has been installed and enabled."
				} ElseIf ($Result -contains 'State : Enable Pending'){
					Write-Warning "WARNING: Line $(LINENUM): .Net Framework 3.5 installed but a reboot is needed."
				} Else {
					Write-Error "ERROR: Line $(LINENUM): .NET Framework 3.5 install failed." -ErrorAction Continue
					If (!($Force)) { Write-Error ("ERROR: Line $(LINENUM):",$Result) -ErrorAction Stop }
				}#End If
			}#End If
		}#End If

		$DotNET = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object{ $_.PSChildName -match '^(?!S)\p{L}'} | Select-Object -ExpandProperty Version
	}#End If

	If (-not ($DotNet -like '3.5.*')){
		If (($Force)) {
			If ($DotNet -match '(?m)^[2-4].\d'){
				Write-Error "ERROR: Line $(LINENUM): .NET 3.5 is not detected and could not be installed." -ErrorAction Continue
			} Else {
				Write-Error "ERROR: Line $(LINENUM): .NET 2.0 or greater is not detected and could not be installed." -ErrorAction Stop
			}#End If
		} Else {
			Write-Error "ERROR: Line $(LINENUM): .NET 3.5 is not detected and could not be installed." -ErrorAction Stop
		}#End If
	}#End If
}

function Get-ADSiteSubnets {
    <#
    .EXAMPLE
    (Get-ADSiteSubnets).subnets

    Name                                    Site
    ----                                    ----
    192.168.111.0/24                        Default-First-Site-Name
    10.1.111.0/24                           Default-First-Site-Name
    192.168.113.0/24                        SF
    192.168.213.0/24                        SF
    #>
    [CmdletBinding()]
    param ()

    $Sites = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites

    foreach ($Site in $Sites) {

        New-Object -Type PSObject -Property @{
            SiteName  = $site.Name
            SubNets = $site.Subnets
            Servers = $Site.Servers
        }
    }
}

function Send-WOL
{
	<# 
	  .SYNOPSIS  
		Send a WOL packet to a broadcast address
	  .PARAMETER mac
	   The MAC address of the device that need to wake up
	  .PARAMETER ip
	   The IP address where the WOL packet will be sent to
	  .EXAMPLE 
	   Send-WOL -mac 00:11:32:21:2D:11 -ip 192.168.8.255 
	#>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,Position=1)]
		[string]$mac,
		[string]$ip="255.255.255.255", 
		[int]$port=9
	)
	
	$broadcast = [Net.IPAddress]::Parse($ip)
	 
	$mac=(($mac.replace(":","")).replace("-","")).replace(".","")
	$target=0,2,4,6,8,10 | % {[convert]::ToByte($mac.substring($_,2),16)}
	$packet = (,[byte]255 * 6) + ($target * 16)
	 
	$UDPclient = new-Object System.Net.Sockets.UdpClient
	$UDPclient.Connect($broadcast,$port)
	[void]$UDPclient.Send($packet, 102) 

}


# Load some external functions
$web = New-Object Net.WebClient
$TheseFunctionsForPstFileInfo = @(
    'https://raw.githubusercontent.com/tonypags/PsWinAdmin/master/Get-DsRegCmdStatus.ps1'
    'https://raw.githubusercontent.com/tonypags/PsWinAdmin/master/Get-CimLocalDisk.ps1'
    'https://raw.githubusercontent.com/tonypags/PsWinAdmin/master/Find-FileByExtension.ps1'
    'https://raw.githubusercontent.com/tonypags/PsWinAdmin/master/Format-ObjectToString.ps1'
    'https://raw.githubusercontent.com/tonypags/PsWinAdmin/master/Find-PstFullName.ps1'
)
Foreach ($uri in $TheseFunctionsForPstFileInfo) {
    $web.DownloadString($uri) | Invoke-Expression
}
$web.Dispose | Out-Null

<#
new draft functions
# >

$cimSplat = @{
    Namespace = 'root/cimv2/mdm/dmmap'
    Class = 'MDM_DevDetail_Ext01'
    Filter = "InstanceID='Ext' AND ParentID='./DevDetail'"
}
Get-CimInstance @cimSplat | Select-Object -ExpandProperty DeviceHardwareData
# For all workstations (edited) 

#>