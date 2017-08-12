<#PSScriptInfo
.VERSION 0.9.0
.GUID 16e3e002-a6d7-4130-b599-5dd23438d194
.AUTHOR Cory Calahan
.COMPANYNAME
.COPYRIGHT (C) Cory Calahan. All rights reserved.
.TAGS SPF,record,DNS
.LICENSEURI
    https://github.com/stlth/Expand-SpfRecord/blob/master/LICENSE
.PROJECTURI
    https://github.com/stlth/Expand-SPFRecord
.ICONURI
.EXTERNALMODULEDEPENDENCIES
#Requires -Modules 'DnsClient'
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
.Synopsis
   Expands a SPF record
.DESCRIPTION
   Expands a SPF record
.EXAMPLE
   PS> Expand-SpfRecord -DomainName 'example.com' -RecurseInclude
.NOTES
   Version:        0.9.0
   Author:         Cory Calahan
   Date:           2017-08-12
   Purpose/Change: Initial function development
#>
<#
.PARAMETER DomainName
   The Internet facing domain name to look up a SPF record TXT for   
.PARAMETER RecurseInclude
    Recursively expand any 'include:' entries for their SPF information from the initial domain name
#>

[CmdletBinding(DefaultParameterSetName='Default', 
                SupportsShouldProcess=$false, 
                ConfirmImpact='Medium')]
[Alias()]
[OutputType([PSObject])]
Param
(
    # Domain name to look-up a SPF Record for
    [Parameter(Mandatory=$true, 
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true, 
                ValueFromRemainingArguments=$false, 
                Position=0,
                ParameterSetName='Default')]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [Alias('Domain')] 
    $DomainName,

    # Recursively expand any 'include:' entries for their information
    [Parameter(ParameterSetName='Default')]
    [switch]
    $RecurseInclude
)

Begin{} # END: BEGIN
Process
{
    foreach ($domain in $DomainName)
    {
        try
        {
            $txt = Resolve-DnsName -Name $domain -Type TXT -DnsOnly -ErrorAction 'Stop'
        }
        catch
        {
            Write-Warning -Message "Domain name '$domain' was not resolved in DNS."
            continue
        }

        $outputObject =[PSCustomObject]@{
            'DomainName' = $domain
            'SPFRecordFound' = $false
            'SPFRecord' = [System.String]::Empty
            'Entry' = New-Object -TypeName 'System.Collections.ArrayList'
        }

        foreach ($string in $txt.Strings)
        {
            Write-Debug -Message "TXT record(s) resolved for '$domain'. Looking at TXT string '$string'."
            # Check if the record is a SPF record, if yes, we will continue
            if ($string.StartsWith('v=spf1'))
            {
                Write-Debug 'Found a SPF TXT record.'
                $outputObject.SPFRecordFound = $true
                $outputObject.SPFRecord = $string

                # Split the text to further walk each component
                $array = $string.Split(' ')

                foreach ($piece in $array)
                {
                    if ($piece -eq 'v=spf1'){
                    Write-Debug -Message "Skipping over 'v=spf1' portion of the string."
                    continue
                    }

                    Write-Debug -Message "Looking at '$piece'."
                    $entry = [PSCustomObject]@{
                        'Qualifier' = 'Default-Neutral'
                        'IsMechanism' = $false
                        'IsModifier' = $false
                        'Mechanism' = [System.String]::Empty
                        'Modifier' = [System.String]::Empty
                        'Component' = $piece
                        'Data' = [System.String]::Empty
                    }
                    # http://www.openspf.org/SPF_Record_Syntax
                    # Qualifier switch
                    # We check if the text includes a leading character. This shows an explicit intent of the immediately following text
                    switch -RegEx ($piece)
                    {
                        '\+' {$entry.Qualifier = 'Pass'}
                        '\-' {$entry.Qualifier = 'Fail'}
                        '\~' {$entry.Qualifier = 'SoftFail'}
                        '\?' {$entry.Qualifier = 'Neutral'}
                    } # End of qualifier switch

                    # Mechanism/Modifier switch
                    # We further check the text to determine if it a mechanism or a modifier.
                    switch -RegEx ($piece)
                    {
                        'all'
                        {
                            $entry.IsMechanism = $true
                            $entry.Mechanism = 'All'
                            $entry.Data = 'all'

                        }
                        'ip4:'
                        {
                            $entry.IsMechanism = $true
                            $entry.Mechanism = 'IP4'
                            $entry.Data = $piece.Split(':')[-1]
                        }
                        'ip6:'
                        {
                            $entry.IsMechanism = $true
                            $entry.Mechanism = 'IP6'
                            $entry.Data = $piece.Split(':')[-1]
                        }
                        'a:'
                        {
                            $entry.IsMechanism = $true
                            $entry.Mechanism = 'A'
                            $entry.Data = $piece.Split(':')[-1]
                        }
                        'mx:'
                        {
                            $entry.IsMechanism = $true
                            $entry.Mechanism = 'MX'
                            $entry.Data = $piece.Split(':')[-1]
                        }
                        'ptr:'
                        {
                            $entry.IsMechanism = $true
                            $entry.Mechanism = 'PTR'
                            $entry.Data = $piece.Split(':')[-1]
                        }
                        'exists:'
                        {
                            $entry.IsMechanism = $true
                            $entry.Mechanism = 'Exists'
                            $entry.Data = $piece.Split(':')[-1]
                        }
                        'include:'
                        {
                            $entry.IsMechanism = $true
                            $entry.Mechanism = 'Include'
                            $entry.Data = $piece.Split(':')[-1]
                        }
                        'redirect='
                        {
                            $entry.IsModifier = $true
                            $entry.Modifier = 'Redirect'
                            $entry.Data = $piece.Split(':')[-1]
                        }
                        'exp='
                        {
                            $entry.IsModifier = $true
                            $entry.Modifier = 'Explaination'
                            $entry.Data = $piece.Split(':')[-1]
                        }
                    } # End of mechanism/modifier switch
                [void]$outputObject.Entry.Add($entry)
                } # End of foreach
            } # End of v=spf1 if
        } # End of string loop

        # SPF Warnings
        # 1 - Exceeds character length
        if ($outputObject.SPFRecordFound -eq $true)
        {
            if ($outputObject.SPFRecord.Length -gt 255){Write-Warning -Message "SPF record length is above maximum (255) character limit: $($outputObject.SPFRecord.Length)"}
            if ($outputObject.Entry.Mechanism.Contains('Modifier'))
            {
                # 2 - Exceeds maximum modifiers
                $redirectcount = $outputObject.Entry.Modifier.Where({$PSItem -eq 'Redirect'}).Count
                if ($redirectcount -gt 1)
                { Write-Warning -Message "SPF record contains more than 1 redirect: ($expcount). A SPF record must only have 1." }
                $expcount = $outputObject.Entry.Modifier.Where({$PSItem -eq 'Explaination'}).Count
                if ($expcount -gt 1)
                { Write-Warning -Message "SPF record contains more than 1 exp: ($expcount). A SPF record must only have 1." }
            }
        }
        # Write the original domain name to the pipeline
        Write-Output -InputObject $outputObject

        if ($RecurseInclude)
        {
            $includes = $outputObject.Entry.Where({$PSItem.Mechanism -eq 'Include'}) | Select-Object -ExpandProperty 'Data'
            if ($includes)
            {
                Write-Debug -Message "Checking additional ($($includes.Count)) include entries..."
                foreach ($include in $includes)
                {
                    $item = $include.Replace('include:','')
                    Expand-SpfRecord -DomainName "$item" -RecurseInclude
                }
            }
            else
            {
                Write-Warning -Message "A recursive lookup of additional include entries for '$domain' was requested, but no further include entries were found."
            }
        } # End recursive include lookup
    } # End processing foreach ($domain in $DomainName)
} # END: PROCESS
End{} # END: END
