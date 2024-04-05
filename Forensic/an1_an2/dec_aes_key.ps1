#-----------------------------------------------------------------------
# RSA Private key (extracted from process memory)
#-----------------------------------------------------------------------
$rsa_private_key='<RSAKeyValue><Modulus>tMWn/H1EhPpLFO9SQwv6qyZrSuUqx4Dv8YUqlDkCvIjr3q1H71Di/2HHZIKRdl6pvV2xAAZVHsAP3YFL4iVMvQPvL8JVvQj6lD46AmNdkt6q7bGtiywK+k7gManNzC9GpTKxYZMgN0jFcV9nZ2dNfIWi1L4jVXsy5DRjUb8tMpVsxmkVNs+H+pWqgLx0Uc1NhN083sLK27MEmL5iFDLdvKVFsT+s5H10Ex2yA+3H+uAVc7luz/zIhLAlq5Ogk0plKB/6E1JlEGQAuq/UkjELp25039KSMjOezQgiGG2gfNTwRkPyXNPekY1pQVjK5VHr2SP55UXuRNrca8hTtxSEvQ==</Modulus><Exponent>AQAB</Exponent><P>6AlvHE86YJSlWDv1PQqtxEyB0FJQzkH416DbMAerMhMesetkvYMNxD42xYdABjtbgsYZqVT7Bxji+2Cp3lmooOxCW7E83V7sVa+FND7PdKCTtIuFIt1bJYIzHfy9FPKPOt97kBPZLP0dOCYiO3FJhhVxtxNCbnhXZCF1vAn0o0s=</P><Q>x3Djz/l/ROpyHX/n3vX9fL02ucq/lU4ihQchKL2vVn4S3XMXLTFP+Nf/xImfq54p5g+Hl+Wn6YoZ/soR5EkTOUF87+1uBq6/lujoK2EL8CAY4w53w+4oXHnk/pnGMWJHfm1JwxeQSgcXvI+TLVNh6SjjUGF2yXq3J8zBmawc6xc=</Q><DP>dM167wc63a815EqaUpXzjuLsXc9x+cHf37uLWowhs11IkEtsNLGp1mVy8M/6fKiYkiXieQjcLGBsshmgqNr9NbR4WuvHNbA4y5FFPl131L+YWsP4yuoena0Cyk+VZtwLGZmx+37iTfFEKiWYCdAnMKXOzleVk0Jky3TEbVmdmi0=</DP><DQ>hRAnnmGa7RLycgYdYJ+EsU3YjlrcObQ4ycJ4+CKeMjnJQmCALRHChocuSSV9F1ZeI/VmhQyfW+xc7aZKC6JJpiCwR6+EggbjIr9f71k/SsVPdWX4uAtUeGaHRuq31cj5ZDtsRDKbfRiAWLj9+/au044JI17zjvdF7dLptCql3J8=</DQ><InverseQ>ypJDZKJdWSiS0a5XTLNSGqg/1y/UIgLAfQjnimrI3mpJECAcp35Ss9a89Ok7bp3kakVvqi5CuK/HWI2UDv3w/8YsAsaEvzSAf8O5DuDIDOpHG28OmmYsrXd8TbMDsT4JFUNBA7fhtcWYg7OHK0HoUDxUT3K25/SmrfMKrYbNp+U=</InverseQ><D>ghL7lkW46QqEvhKamZ3kCAUEDQcrKhTQEnSkt7TyECFhv3/mFACa5fJAnEULUCY7cwQYmZD07MR8ZgFkTdxTBGrxT+dA9F2imMrRyOgg686HJbPE0TCm0Yex8Gpjp/mYlsQMOM65zq3xTGu+pvwBGIm8KeKK4DZe3zAHC0pJxmviOP51AyQCLKQaalLfZLngSzeT3KZ3h0Af2rB0LCSj3DlNxu4PK7uWWxIlf9HyAJwTO0rgeegE2+WldvddPnwC6rhor43b2c4ExsYVCk6xYre6dUaTJ7evdHRRMjMkHkTg39PJzq/mxSER82xj7mR9opMohe3qPp+Kh1+uNaIhDQ==</D></RSAKeyValue>'

#Write-Output '## RSA Private key (extracted from process memory):'
#Write-Output $rsa_private_key
#Write-Output ''

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
