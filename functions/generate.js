// functions/generate.js
export async function onRequest(context) {
  // POST method ကိုပဲ ခွင့်ပြုပါ
  if (context.request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  // Handle OPTIONS preflight request
  if (context.request.method === "OPTIONS") {
    return new Response("", { status: 204, headers });
  }

  try {
    // Generate X25519 key pair using Web Crypto API
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "X25519",
      },
      true,
      ["deriveKey", "deriveBits"]
    );

    // Export private key as PKCS#8
    const privateKeyRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const privateKeyBytes = new Uint8Array(privateKeyRaw);
    // Remove PKCS#8 header (first 16 bytes for X25519)
    const priv = btoa(String.fromCharCode(...privateKeyBytes.slice(16)));

    // Export public key as SPKI
    const publicKeyRaw = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyBytes = new Uint8Array(publicKeyRaw);
    // Remove SPKI header (first 12 bytes for X25519)
    const pub = btoa(String.fromCharCode(...publicKeyBytes.slice(12)));

    // Generate random install ID (11 bytes hex)
    const installIdBytes = crypto.getRandomValues(new Uint8Array(11));
    const installId = Array.from(installIdBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // Generate random FCM token (67 bytes base64)
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
      headers: {
        "User-Agent": "okhttp/3.12.1",
        "Content-Type": "application/json; charset=UTF-8",
      },
      body: JSON.stringify(body),
    });

    let configStr = "";

    if (warpRes.ok) {
      const data = await warpRes.json();
      const v4 = data.config.interface.addresses.v4;
      const v6 = data.config.interface.addresses.v6;
      const peerPub = data.config.peers[0].public_key;
      configStr =
`[Interface]
PrivateKey = ${priv}
Address = ${v4}/32
Address = ${v6}/128
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280

[Peer]
PublicKey = ${peerPub}
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = 162.159.192.3:500
PersistentKeepalive = 20`;
    } else {
      configStr =
`[Interface]
PrivateKey = ${priv}
Address = 172.16.0.2/32
Address = 2606:4700:110:8f81:d551:a0:532e:a2b3/128
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = 162.159.192.3:500
PersistentKeepalive = 20`;
    }

    // Keep the original format (no prefix modification)
    const finalConfig = configStr;

    return new Response(
      JSON.stringify({ config: finalConfig }),
      { status: 200, headers }
    );

  } catch (err) {
    console.error("Error:", err);
    return new Response(
      JSON.stringify({ message: "Failed to generate configuration." }),
      { status: 500, headers }
    );
  }
}
