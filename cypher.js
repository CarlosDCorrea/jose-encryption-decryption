/**
* Importacion modulos necesarios
*/
const { JWE, JWK } = require('node-jose');

encrypt = async (data) => {

    /**
    * Creacion de las llaves para el cifrado de la solicitud y respuesta ENTREGADA POR TBK
    */
    // Llave publica entrega por Transbank
    
    const keyCloud = `-----BEGIN CERTIFICATE-----
your cert
    -----END CERTIFICATE-----`;

    const keyQA = `-----BEGIN CERTIFICATE-----
your cert
    -----END CERTIFICATE-----`

    const key = keyCloud;

    let publicKey = await JWK.asKey(key, "pem");

    console.log("public key::", publicKey);
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Llave pública que se envia a través del header protegido debe estar en formato JWK
    const publicKeyJWK = {
        "kty": "RSA",
        "e": "AQAB",
        "use": "enc",
        "kid": "KSA_TvwSIG3dPkMtlTdk4KjZ5Ni6DJlNO6n2QmKxxp0",
        "alg": "RSA-OAEP-256",
        "n": "vOJbjB87amMl0tO8IcK1esLI3eByrGkwSicTWLEqjbFDw9A-rMh47ZAKZEDUTqZ6NFc3g3_i4yy3VsgMnsQo1kpsgr0Sxa6O-UOr1TGFYNCMEDecdP2uc5DSTiRBkMpAd_jJ-jAe-DPwalpFviLbvVbFepMuHcKSXfjUSfYkVWoxsduGMdTKfJeavRnB5V4fjQ5xdF1vNaoqmJ8NQp88_RmYDi4KwvD80WdGzL-Hj19tH4bVk4XG8tVUYaUkRrVTBAnAMRVgpK3nZV2Ga-aHxCSioQoyjCLPerQIb40gP-AmL7yuryPsTZVzqGpBmNaIRaG7ExsqonvZd_HHzQ0j8w"
    };

    const jwkPK = await JWK.asKey(publicKeyJWK, "json");

    const buffer = Buffer.from(JSON.stringify(data));

    /**
    * Cifrado del mensaje
    */
    const encrypted = await JWE.createEncrypt(
        {
            format: 'compact', // Formato de mensajería
            contentAlg: 'A256GCM', // Algoritmo de cifrado del mensaje
            fields: {
                alg: 'RSA-OAEP-256', // Algoritmo en el que se cifra la llave simétrica generada aleatoriamente por la librería
                'key': JSON.stringify(jwkPK) // Llave pública generada para cifrar la respuesta
            }
        },
        publicKey) // Llave publica de Transbank
        .update(buffer).final();

    console.log(encrypted);
    return encrypted;
}

// tbkToken
let json = {
    data: ""
 };

let data = json;

encrypt(data);