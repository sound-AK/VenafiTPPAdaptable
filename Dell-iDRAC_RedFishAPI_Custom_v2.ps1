<#
// -----------------------------------------
// Dell-iDRAC_RedFishAPI.ps1
//
// Copyright (c) 2019-2025 Venafi, Inc.  All rights reserved.
//
//
// This sample script and its contents are provided by Venafi to customers
// and authorized technology partners for the purposes of integrating with
// services and platforms that are not owned or supported by Venafi.  Any
// sharing of this script or its contents without consent from Venafi is
// prohibited.
//
// This sample is provided "as is" without warranty of any kind.
//
//-----------------------------------------------------------------------

<field name>|<label text>|<flags>

Bit 1 = Enabled
Bit 2 = Policyable
Bit 3 = Mandatory

-----BEGIN FIELD DEFINITIONS-----
Text1|Not Used|000
Text2|Not Used|000
Text3|Not Used|000
Text4|Not Used|000
Text5|Not Used|000
Option1|Not Used|000
Option2|Not Used|000
Passwd|Not Used|000
-----END FIELD DEFINITIONS-----
#>



<######################################################################################################################
.NAME
    Generate-CSR
.DESCRIPTION
    Remotely generates a CSR on the hosting platform.  Remote generation is considered UNSUPPORTED
    if this function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        SubjectDN : the requested subject distiguished name as a hashtable; OU is a string array; all others are strings
        SubjAltNames : hashtable keyed by SAN type; values are string arrays of the individual SANs
        KeySize : the integer key size to be used when creating a key pair
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        Pkcs10 : a string representation of the CSR in PKCS#10 format
        AssetName : (optional) the base name used to reference the certificate as it was installed on the device;
                    if not supplied the auto-generated name is assumed
######################################################################################################################>
function Generate-CSR
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    return @{ Result="NotUsed" }
}


<######################################################################################################################
.NAME
    Install-Certificate
.DESCRIPTION
    Installs the certificate on the hosting platform.  May optionally be used to also install the private key and chain.
    Implementing logic for this function is REQUIRED.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        CertPem : the X509 certificate to be provisioned in Base64 PEM format
        PrivKeyPem : the non-encrypted private key in RSA Base64 PEM format
        PrivKeyPemEncrypted : the password encrypted private key in RSA Base64 PEM format
        ChainPem : all chain certificates concatentated together one after the other
        ChainPkcs7 : byte array PKCS#7 collection that includes all chain certificates
        Pkcs12 : byte array PKCS#12 collection that includes certificate, private key, and chain
        EncryptPass : the string password that was used to encrypt the private key and PKCS#12 keystore
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state
                 (may only be 'NotUsed' if Install-PrivateKey did not return 'NotUsed')
        AssetName : (optional) the base name used to reference the certificate as it was installed on the device;
                    if not supplied the auto-generated name is assumed

R f rence : https://docs.venafi.com/Docs/current/TopNav/Content/Drivers/r-drivers-AdaptableApp-function-Install-Certificate.php?tocpath=TLS%20Protect%7CCertificate%20Authority%20and%20Hosting%20Platform%20Integration%20Guide%7CProtecting%20server%20platforms%20and%20keystores%7CAdaptable%20Application%7CPowerShell%20script%20reference%20for%20Adaptable%20Application%7C_____11
######################################################################################################################>
function Install-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    $addr = $General.HostAddress
    $user = $General.UserName
    $pass = $General.UserPass
    $p12 =  $Specific.Pkcs12
    $encPass = $Specific.EncryptPass
    $pem = $Specific.CertPem

    <#if ( $Specific.Pkcs12 )
    {
        throw "'Generate Key/CSR on Application' must be set to 'Yes' to provision this certificate."
    }#>

    try {
        Write-VenafiDebug -Message "The login address is $addr, the username is $user & the password is $pass"
        $Rep_OuvSes = New_iDRACSession $addr, $user, $pass
        $Rep_OuvSes | Write-VenafiDebug
    }
    catch {
        Write-VenafiDebug -Message "Failed : $_"
        return @{ Result="Failed"; AssetName="Not Applicable" }
    }

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("X-Auth-Token", $Rep_OuvSes.'X-Auth-Token' )

Function ConvertTo-Base64 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Collections.ArrayList]
        $Data
    )

    "Converting the Pkcs12 certificate representation byte array to Base64 encoded format." | Write-VenafiDebug
    $output = [System.Convert]::ToBase64String($Data)
    $output = $output -replace "(.{64})", "`$1`n"
    $output = $output.TrimEnd("`r`n")
    return $output
}

    $base64Str = ConvertTo-Base64 -Data $p12
    <#$paddedStr = do {
        $base64Str[0..63] -join ''
        $base64Str = $base64Str[64..$($base64Str.length)]
    } until ($base64Str.Length -eq 0)#>

    Write-VenafiDebug -Message "The base64 string is $base64Str"

    $body = @{"CertificateType"= "CustomCertificate"; "SSLCertificateFile" = $base64Str}
    
    $body["Passphrase"] = $encPass
    
    $JSONbody = $body | ConvertTo-Json -Compress

    Write-VenafiDebug -Message "The body is $JSONbody"

    $LienPOST = "https://" + $addr +"/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/Actions/DelliDRACCardService.ImportSSLCertificate"

    try {
        Ignore-SSLCertificates
        $Rep_Post = Invoke-WebRequest -UseBasicParsing -Uri $LienPOST -Method Post -Body $JSONbody -ContentType 'application/json' -Headers $headers -ErrorVariable RespErr
    }
    catch {
        Write-VenafiDebug -Message "Failed : $RespErr"
        return @{ Result="Failed"; AssetName="Not Applicable" }
    }
    if ($Rep_Post.StatusCode -eq 200 -or $Rep_Post.StatusCode -eq 202)
    {
    [String]::Format("-PASS,{0} SSL Cert Operation passed")
    }
    return @{ Result="Success"; AssetName="Not Applicable" }
}


<######################################################################################################################
.NAME
    Prepare-KeyStore
.DESCRIPTION
    Remotely create and/or verify keystore on the hosting platform.  Remote generation is considered UNSUPPORTED if this
    function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions
        HostAddress : a string containing the hostname or IP address specified by the device object
        TcpPort : an integer value containing the TCP port specified by the application object
        UserName : a string containing the username portion of the credential assigned to the device or application object
        UserPass : a string containing the password portion of the credential assigned to the device or application object
        UserPrivKey : the non-encrypted PEM of the private key credential assigned to the device or application object
        AppObjectDN : a string containing the TPP distiguished name of the calling application object
        AssetName : a string containing a Venafi standard auto-generated name that can be used for provisioning
                    (<Common Name>-<ValidTo as YYMMDD>-<Last 4 of SerialNum>)
        VarText1 : a string value for the text custom field defined by the header at the top of this script
        VarText2 : a string value for the text custom field defined by the header at the top of this script
        VarText3 : a string value for the text custom field defined by the header at the top of this script
        VarText4 : a string value for the text custom field defined by the header at the top of this script
        VarText5 : a string value for the text custom field defined by the header at the top of this script
        VarBool1 : a boolean value for the yes/no custom field defined by the header at the top of this script (true|false)
        VarBool2 : a boolean value for the yes/no custom field defined by the header at the top of this script (true|false)
        VarPass : a string value for the password custom field defined by the header at the top of this script
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
######################################################################################################################>
function Prepare-KeyStore
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    return @{ Result="NotUsed"; }
}


<######################################################################################################################
.NAME
    Generate-KeyPair
.DESCRIPTION
    Remotely generates a public-private key pair on the hosting platform.  Remote generation is
    considered UNSUPPORTED if this function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        KeySize : the integer key size to be used when creating a key pair
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        AssetName : (optional) the base name used to reference the certificate as it was installed on the device;
                    if not supplied the auto-generated name is assumed
######################################################################################################################>
function Generate-KeyPair
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    return @{ Result="NotUsed" }
}


<######################################################################################################################
.NAME
    Install-Chain
.DESCRIPTION
    Installs the certificate chain on the hosting platform.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        ChainPem : all chain certificates concatentated together one after the other
        ChainPkcs7 : byte array PKCS#7 collection that includes all chain certificates
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state
######################################################################################################################>
function Install-Chain
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    return @{ Result="NotUsed" }
}


<######################################################################################################################
.NAME
    Install-PrivateKey
.DESCRIPTION
    Installs the private key on the hosting platform.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        PrivKeyPem : the non-encrypted private key in RSA Base64 PEM format
        PrivKeyPemEncrypted : the password encrypted private key in RSA Base64 PEM format
        EncryptPass : the string password that was used to encrypt the private key and PKCS#12 keystore
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state
        AssetName : (optional) the base name used to reference the private key as it was installed on the device;
                    if not supplied the auto-generated name is assumed
######################################################################################################################>
function Install-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    return @{ Result="NotUsed" }
}


<######################################################################################################################
.NAME
    Update-Binding
.DESCRIPTION
    Binds the installed certificate with the consuming application or service on the hosting platform
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
######################################################################################################################>
function Update-Binding
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    return @{ Result="NotUsed"; }
}


<######################################################################################################################
.NAME
    Activate-Certificate
.DESCRIPTION
    Performs any post-installation operations necessary to make the certificate active (such as restarting a service)
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
######################################################################################################################>
function Activate-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    return @{ Result="NotUsed"; }
}


<######################################################################################################################
.NAME
    Extract-Certificate
.DESCRIPTION
    Extracts the active certificate from the hosting platform.  If the platform does not provide a method for exporting the
    raw certificate then it is sufficient to return only the Serial and Thumprint.  This function is REQUIRED.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        CertPem : the extracted X509 certificate referenced by AssetName in Base64 PEM format
        Serial : the serial number of the X509 certificate refernced by AssetName
        Thumbprint : the SHA1 thumprint of the X509 certificate referenced by AssetName
######################################################################################################################>
function Extract-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    return @{ Result="NotUsed" }
}


<######################################################################################################################
.NAME
    Extract-PrivateKey
.DESCRIPTION
    Extracts the private key associated with the certificate from the hosting platform
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        EncryptPass : the string password to use when encrypting the private key
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        PrivKeyPem : the extracted private key in RSA Base64 PEM format (encrypted or not)
######################################################################################################################>
function Extract-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    return @{ Result="NotUsed" }
}


<######################################################################################################################
.NAME
    Remove-Certificate
.DESCRIPTION
    Removes an existing certificate (or private key) from the device.  Only implement the body of
    this function if TPP can/should remove old generations of the same asset.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        AssetNameOld : the name of a asset that was previously replaced and should be deleted
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
######################################################################################################################>
function Remove-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Write-FunctionDetail $PSCmdlet.MyInvocation

    return @{ Result="NotUsed"; }
}

<###################### THE FUNCTIONS AND CODE BELOW THIS LINE ARE NOT CALLED DIRECTLY BY VENAFI ######################>


####### Allows the opening of a work session while retrieving the authentication key ##########

function New_iDRACSession {

     Write-VenafiDebug -Message "Login to $addr"

# Allows all tls formats
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12

    # Allows you to bypass certificate validation.
    function Ignore-SSLCertificates {
        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Compiler = $Provider.CreateCompiler()
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $false
        $Params.GenerateInMemory = $true
        $Params.IncludeDebugInformation = $false
        $Params.ReferencedAssemblies.Add("System.DLL") > $null
        $TASource = @'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
        $TAResults = $Provider.CompileAssemblyFromSource($Params, $TASource)
        $TAAssembly = $TAResults.CompiledAssembly
        ## We create an instance of TrustAll and attach it to the ServicePointManager
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
    }

        $user = $user
        $pass = $pass
        $addr = $addr
        $secpasswd = ConvertTo-SecureString $pass -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($user, $secpasswd)

    function get_redfish_version {
        $uri = "https://$addr/redfish/v1"
        try {
                Ignore-SSLCertificates
                $result = Invoke-WebRequest -Uri $uri -Credential $credential -Method Get -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json" }
            }
        catch {
            Write-VenafiDebug
            $RespErr
            return
        }

        $global:get_redfish_version = (($result.Content | ConvertFrom-Json).RedfishVersion).replace('.', '')
    }

    get_redfish_version 

    $uri = if ($global:get_redfish_version -ge 160) {
        "https://$addr/redfish/v1/SessionService/Sessions"
    }
    elseif ($global:get_redfish_version -lt 160) {
        "https://$addr/redfish/v1/Sessions"
    }
    else {
        Write-VenafiDebug -Message "`n- ERROR, unable to select URI based off Redfish version"
        break
    }

    $uri | Write-VenafiDebug

    $body = @{'UserName' = $user; 'Password' = $pass } | ConvertTo-Json -Compress

    try {
         Ignore-SSLCertificates
         $result = Invoke-WebRequest -Uri $uri -Body $body -Method Post -UseBasicParsing -ErrorVariable RespErr -Headers @{"Accept" = "application/json" } -ContentType 'application/json'
    }
    catch {
          Write-VenafiDebug
          $RespErr
          return
    }

    if ($result.StatusCode -eq 201) {
    }
     else {
            [String]::Format("`n- FAIL, POST request failed to create X-Auth token session, statuscode {0} returned", $result.StatusCode)
            return
        }

        Write-VenafiDebug "`n- PASS, new iDRAC token session successfully created`n"
        $result.Headers
}

############################# Sanitization of character strings ###############################

function Sanitize-String( [string] $name, [string] $value )
{
    # we will silently discard any invalid characters but raise an exception if the value is too long

    switch ($name)
    {
        "Common Name" { $max_len=61; $valid_chars="[^a-zA-Z0-9 _\-\.\@\*\|\?\/\:\<\>\,\#\$\%\^\&\(\)\{\}\[\]\\\/]"; break }
        "Organizational Unit" { $max_len=61; $valid_chars="[^a-zA-Z0-9 _\-\.\?\/\:\,\(\)\/]"; break }
        "Organization" { $max_len=61; $valid_chars="[^a-zA-Z0-9 _\-\.\?\/\:\,\(\)\/]"; break }
        "City" { $max_len=51; $valid_chars="[^a-zA-Z ]"; break }
        "State" { $max_len=31; $valid_chars="[^a-zA-Z ]"; break }
        "Country" { $max_len=2; $valid_chars="[^a-zA-Z]"; break }
        default { $max_len=61; $valid_chars="[^a-zA-Z0-9 _\-\.]"; break }
    }

    $out = $value -replace $valid_chars,""

    if ( $out.Length -gt $max_len )
    {
        throw "iDRAC does not allow {0} value to exceed {1} characters ({2})" -f $name, $max_len, $out
    }

    return $out
}

#############################     Debug logging functions     #################################

Function Write-FunctionDetail {

    <#
    .SYNOPSIS
        Log function details
    .DESCRIPTION
        Log function details including the function name and any bound parameters
    .NOTES
        Must be an advanced function otherwise $PSCmdlet.MyInvocation will not be available.
        Set $script:scriptVersion to include the script version in the log.
    .EXAMPLE
        Write-FunctionDetail $PSCmdlet.MyInvocation

        Put this at the start of every function
    .EXAMPLE
        Write-FunctionDetail $PSCmdlet.MyInvocation -NoBoundParams

        Do not output the bound parameters
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [System.Management.Automation.InvocationInfo] $InvocationInfo,

        [Parameter()]
        [switch] $NoBoundParams
    )

    $header = 'Function: {0}' -f $InvocationInfo.InvocationName
    $header += if ($script:scriptVersion) { ', script version: {0}' -f $script:scriptVersion } else { '' }
    $header | Write-VenafiDebug

    if ( $null -ne $InvocationInfo.BoundParameters -and -not $NoBoundParams ) {
        [hashtable]$InvocationInfo.BoundParameters | Write-VenafiDebug
    }
}

function Write-VenafiDebug {

    <#
    .SYNOPSIS
    Write info to the adaptable debug log

    .DESCRIPTION
    Assuming the option has been selected, write info to the adaptable debug log.
    Hashtables are supported and secret info will not be logged, eg. $General.

    .PARAMETER Message
    The info to be logged

    .PARAMETER ThrowException
    After logging the message, throw an exception to terminate the script

    .EXAMPLE
    Write-VenafiDebug -Message 'connected to server'

    Write info to the log

    .EXAMPLE
    $General | Write-VenafiDebug

    Write input parameter values to the log

    .EXAMPLE
    Write-VenafiDebug -Message 'this was not good' -ThrowException

    Write to the log and throw an exception
    #>

    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Message,

        [Parameter()]
        [string] $Intro,

        [Parameter()]
        [switch] $ThrowException
    )

    process {

        if ( -not $global:DEBUG_FILE ) {
            return
        }

        $newMessage = switch ($Message.GetType().FullName) {
            'System.Collections.Hashtable' {
                Set-SecretsToHidden $Message | ConvertTo-Json -Depth 5
            }

            'System.String' {
                $Message
            }

            'System.Management.Automation.ErrorRecord' {
                # powershell specific exception
                $err = $Message
                $ex = $err.Exception
                $inv = $err.InvocationInfo
                $logEntry = @{
                    Message          = $ex.Message
                    ErrorId          = $err.FullyQualifiedErrorId
                    Category         = $err.CategoryInfo.Category
                    TargetObject     = $err.TargetObject
                    ScriptName       = $inv.ScriptName
                    LineNumber       = $inv.ScriptLineNumber
                    Line             = $inv.Line
                    Position         = $inv.PositionMessage
                    StackTrace       = $ex.StackTrace
                    ScriptStackTrace = $err.ScriptStackTrace
                }
                if ($ex.InnerException) {
                    $logEntry.InnerExceptionMessage = $ex.InnerException.Message
                    $logEntry.InnerExceptionType = $ex.InnerException.GetType().FullName
                }
                $logEntry | ConvertTo-Json -Depth 3
            }

            'System.Exception' {
                #.net generic exception
                $ex = $Message
                $inv = $ex.InvocationInfo
                $logEntry = @{
                    Message       = $ex.Message
                    ExceptionType = $ex.GetType().FullName
                    ScriptName    = $inv.ScriptName
                    LineNumber    = $inv.ScriptLineNumber
                    Line          = $inv.Line
                    Position      = $inv.PositionMessage
                    StackTrace    = $ex.StackTrace
                }
                if ($ex.InnerException) {
                    $logEntry.InnerExceptionMessage = $ex.InnerException.Message
                    $logEntry.InnerExceptionType = $ex.InnerException.GetType().FullName
                }

                $logEntry | ConvertTo-Json -Depth 3
            }

            default {
                $Message | ConvertTo-Json -Depth 3
            }
        }

        if ( $Intro ) {
            $newMessage = "$Intro`r`n$newMessage"
        }

        try {
            # use a mutex to ensure multiple executions of this script don't cause 'file in use' errors
            $mutex = New-Object System.Threading.Mutex($false, [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName))
            if ( -not $mutex.WaitOne(0) ) {
                $mutex.WaitOne()
            }
            ('{0} : {1}' -f (Get-Date), ($newMessage | Out-String)) | Out-File -FilePath $global:DEBUG_FILE -Encoding 'UTF8' -Append
        }
        catch {
            throw $_
        }
        finally {
            $null = $mutex.ReleaseMutex()
        }
    }

    end {
        if ( $ThrowException ) {
            # since we're in the end block this is only intended for a string, not array or anything that needs the pipeline
            throw $Message
        }
    }
}

function Set-SecretsToHidden {

    <#
    .SYNOPSIS
        Blank out sensitive information
    .DESCRIPTION
        Blank out sensitive information in a message, typically in a hashtable.
        Meant for adaptable framework scripts.
        Will automatically clone hashtable to ensure original object isn't affected.
    #>


    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject
    )

    process {

        $secrets = @('UserPass', 'AuxPass', 'PfxPass', 'Certificate', 'PfxData', 'Password', 'AuxPfxData', 'PrivKeyPem', 'Pkcs12', 'EncryptPass', 'ChainPkcs7', 'PrivKeyPemEncrypted', 'VarPass')

        # if needed, add additional secrets specific to this integration to be hidden
        # $secrets += '', ''

        if ($InputObject -is [hashtable]) {
            $clone = @{}
            foreach ($key in $InputObject.keys) {
                if ( [string]::IsNullOrEmpty($InputObject[$key]) ) {
                    $clone[$key] = ''
                }
                else {
                    if ($key -in $secrets ) {
                        $clone[$key] = '***hidden***'
                    }
                    else {
                        $clone[$key] = Set-SecretsToHidden $InputObject[$key]
                    }
                }
            }
            return $clone
        }
        else {
            return $InputObject
        }
    }
}
 


#############################   Function to ignore SSL certs ##################################

function Ignore-SSLCertificates
{
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler = $Provider.CreateCompiler()
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $false
    $Params.GenerateInMemory = $true
    $Params.IncludeDebugInformation = $false
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}


