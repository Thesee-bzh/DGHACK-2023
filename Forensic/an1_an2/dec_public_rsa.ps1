function Decrypt-Bytes {
    param ($Key, $In)
    if($In.Length -gt 32)
    {
	$HMAC = New-Object System.Security.Cryptography.HMACSHA256;
    	$e=[System.Text.Encoding]::ASCII;
    	$Mac = $In[-10..-1];
    	$In = $In[0..($In.length - 11)];
    	$hmac.Key = $e.GetBytes($Key);
	$Expected = $hmac.ComputeHash($In)[0..9];
    	if (@(Compare-Object $Mac $Expected -Sync 0).Length -ne 0) {return;}
    	$IV = $In[0..15];
    	try {$AES=New-Object System.Security.Cryptography.AesCryptoServiceProvider;}
    	catch {$AES=New-Object System.Security.Cryptography.RijndaelManaged;}
    	$AES.Mode = "CBC";
    	$AES.Key = $e.GetBytes($Key);
    	$AES.IV = $IV;
    	($AES.CreateDecryptor()).TransformFinalBlock(($In[16..$In.length]), 0, $In.Length-16)
    }
}

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