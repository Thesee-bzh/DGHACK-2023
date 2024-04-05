# Crypto / AEgisSecureForge (part1)

## Challenge
La campagne de crowdfunding pour les robots AEgisSecureForge s'est terminée dans une grande déception. Les robots que nous avons finalement reçus, avec un an de retard, ne correspondent en rien à ce qui nous avait été promis. Il y a quelques jours, l'entreprise a réuni un groupe d'influenceurs pour dévoiler ses projets futurs, et il est devenu clair qu'ils prévoient de basculer vers un modèle B2B. Malheureusement, cela signifie la fin définitive du support pour nos robots.

Avant la réunion, j'avais déjà des doutes quant à leurs intentions. Les prétendus problèmes de stabilité des serveurs ne laissaient rien présager de bon. Même s'ils ont tenté de nous rassurer, j'ai eu l'impression d'entendre une conversation entre deux développeurs dans la salle de pause, évoquant une mise à jour visant à rendre inopérants les robots de génération précédente, probablement les nôtres. J'ai profité de l'occasion pour effectuer une capture réseau dans leurs locaux. Bien que je n'aie pas encore trouvé la dernière version du firmware qu'ils mentionnaient, je garde l'espoir de la récupérer.

Cependant, je ne peux pas y parvenir seul. C'est pourquoi je fais appel à vos compétences pour m'aider à récupérer le firmware, en utilisant la capture réseau que je mets à votre disposition ici. J'espère que nous pourrons trouver des preuves de cette manœuvre pour les diffuser publiquement, afin d'éviter à un maximum d'utilisateurs de voir leurs robots devenir inutilisables.

## Inputs
- PCAP file [aegis.pcapng](./aegis.pcapng)


## Solution
In the `PCAP` file, we see some `HTTP` traffic, especially this request:
```http
GET /?960f29ac832bfe36 HTTP/1.1
Host: valence.mikeofp.free.fr
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:6.0) Gecko/20110814 Firefox/6.0 AEgisChatBot UriPreview/0.5
X-Original-Url: http://valence.mikeofp.free.fr/?960f29ac832bfe36#2VPy/R1GCQubXa36xPmxB5TR7HfTchPQF9Wz+P+9Xqs=
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
```

Apparently, http://valence.mikeofp.free.fr is a self-hosted instance of `PrivateBin` (https://privatebin.net/), something similar to a `pastebin`.

From the `PrivateBin` website:

> PrivateBin is a minimalist, open source online pastebin where the server has zero knowledge of pasted data. Data is encrypted/decrypted in the browser using 256 bits AES.

So we go to to that URL:

> http://valence.mikeofp.free.fr/?960f29ac832bfe36#2VPy/R1GCQubXa36xPmxB5TR7HfTchPQF9Wz+P+9Xqs=

Unfortunately, the `pastebin` has already expired... But we can recover it from the `PCAP` file, which logged the past retrieval of the `pastebin` !

Here we go:
```html
<div id="cipherdata" class="hidden">{"meta":{"expire_date":1700438697,"burnafterreading":true,"opendiscussion":false,"formatter":"plaintext","postdate":1699833897,"remaining_time":604788},"data":"{\"iv\":\"3IZ8loiaVy4MowXCP+WBIQ==\",\"v\":1,\"iter\":1000,\"ks\":256,\"ts\":128,\"mode\":\"gcm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"0VndpPRdv3g=\",\"ct\":\"EClLmRtbbzGDP\/1JqY\(...)
```

What's missing is the cipher key. But the way `PrivateBin` works, the cipher key is included in the URL, after the `#` sign. So here's the key:

> key = '2VPy/R1GCQubXa36xPmxB5TR7HfTchPQF9Wz+P+9Xqs='


Now we also need to look at the `javascript` to see how the decryption works. In `privatebin.js`, there's a function `decipher(key, password, data)` which does exactly what we want in object `jQuery.PrivateBin.CryptTool`. We just pass en empty `password`, because... we don't have any !

Here's some `javascript` to decrypt it:
```js
const key = "2VPy/R1GCQubXa36xPmxB5TR7HfTchPQF9Wz+P+9Xqs=";
const data = '{"iv":"3IZ8loiaVy4MowXCP+WBIQ==","v":1,"iter":1000,"ks":256,"ts":128,"mode":"gcm","adata":"","cipher":"aes","salt":"0VndpPRdv3g=","ct":"EClLmRtbbzGDP/1JqY/kfWKV1GdLAi7khBjdE+(...)"}';
console.log(jQuery.PrivateBin.CryptTool.decipher(key, "", data));
```

We get some secret message from Zack to John, some python crypto code `server.py` (to be used in part2) and the first flag !


> Hi John,
>
> I'm sick today, so I can't make it to the office. As I told you on telegram, last night, I fixed the issue with ticket 202 regarding the update server.
> Here's the updated source code. I didn't leave any comments, but if you have any questions, feel free to give me a call.
> I'll do my best to respond over the phone. I know you can handle it.
>
> I should be back next week. Take care.
>
> See you soon,
> Zack

## First flag

> DGHACK{ThisCodeSmellGood,No?}
