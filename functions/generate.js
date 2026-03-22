// functions/generate.js
export async function onRequest(context) {
  const { request } = context;
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  if (request.method === "OPTIONS") {
    return new Response("", { status: 204, headers });
  }

  try {
    // Generate X25519 key pair
    const keyPair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveKey", "deriveBits"]);
    const privateKeyRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const privateKeyBytes = new Uint8Array(privateKeyRaw);
    const priv = btoa(String.fromCharCode(...privateKeyBytes.slice(16)));
    const publicKeyRaw = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyBytes = new Uint8Array(publicKeyRaw);
    const pub = btoa(String.fromCharCode(...publicKeyBytes.slice(12)));

    const installIdBytes = crypto.getRandomValues(new Uint8Array(11));
    const installId = Array.from(installIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const fcmTokenBytes = crypto.getRandomValues(new Uint8Array(67));
    const fcmTokenSuffix = btoa(String.fromCharCode(...fcmTokenBytes));

    const body = {
      key: pub,
      install_id: installId,
      fcm_token: installId + ":APA91b" + fcmTokenSuffix,
      tos: new Date().toISOString(),
      model: "Android",
      type: "Android",
      locale: "en_US",
    };

    const warpRes = await fetch("https://api.cloudflareclient.com/v0a884/reg", {
      method: "POST",
      headers: { "User-Agent": "okhttp/3.12.1", "Content-Type": "application/json; charset=UTF-8" },
      body: JSON.stringify(body),
    });

    let configStr = "";
    if (warpRes.ok) {
      const data = await warpRes.json();
      const v4 = data.config.interface.addresses.v4;
      const v6 = data.config.interface.addresses.v6;
      const peerPub = data.config.peers[0].public_key;
      configStr = `[Interface]\nPrivateKey = ${priv}\nAddress = ${v4}/32\nAddress = ${v6}/128\nDNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001\nMTU = 1280\n\n[Peer]\nPublicKey = ${peerPub}\nAllowedIPs = 0.0.0.0/0\nAllowedIPs = ::/0\nEndpoint = 162.159.192.3:500\nPersistentKeepalive = 20`;
    } else {
      configStr = `[Interface]\nPrivateKey = ${priv}\nAddress = 172.16.0.2/32\nAddress = 2606:4700:110:8f81:d551:a0:532e:a2b3/128\nDNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001\nMTU = 1280\n\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nAllowedIPs = 0.0.0.0/0\nAllowedIPs = ::/0\nEndpoint = 162.159.192.3:500\nPersistentKeepalive = 20`;
    }

    return new Response(JSON.stringify({ config: configStr }), { status: 200, headers });
  } catch (err) {
    return new Response(JSON.stringify({ message: "Failed to generate configuration." }), { status: 500, headers });
  }
}
