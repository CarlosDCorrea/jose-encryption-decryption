/**
* Importacion modulos necesarios
*/
const jose = require('jose');
var jwe;

const alg = 'RSA-OAEP-256';
const x509 = `-----BEGIN CERTIFICATE-----
your cert
-----END CERTIFICATE-----`

var publicKeyOuter;
var jwkpubk;
var jwkprivk;

async function getJWKPair() {
    const { publicKey, privateKey } = await jose.generateKeyPair(alg)
    jwkpubk = publicKey;
    jwkprivk = privateKey;
}

jose.importX509(x509, alg).then(pubKeyObj => {
    publicKeyOuter = pubKeyObj
    getJWE();
});

async function getJWE() {
    await getJWKPair();

    let data = {
        data: ""
    }

    jwe = await new jose.CompactEncrypt(
        new TextEncoder().encode(JSON.stringify(data)),
    )
        .setProtectedHeader(
            {
                alg: 'RSA-OAEP-256',
                enc: 'A256GCM'
            }
        )
        .encrypt(jwk);

    console.log(jwe);

    decrypt(jwe);
}

async function decrypt() {
    const { plaintext, protectedHeader } = await jose.compactDecrypt(jwe, jwkprivk);

    console.log(protectedHeader);
    console.log(new TextDecoder().decode(plaintext))
}