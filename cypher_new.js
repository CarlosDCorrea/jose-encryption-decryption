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
        "header": {
            "tpdu": "00201",
            "DeviceType": "9.",
            "TranNumber": "100",
            "TerminalId": "ECOPEC1640008933",
            "EmployeeId": "      ",
            "CurrentDate": "230420",
            "CurrentTime": "164150",
            "MessageType": "F",
            "MessageSubtype": "O",
            "TransactionCode": "01",
            "ProcessingFlag1": "0",
            "ProcessingFlag2": "5",
            "ProcessingFlag3": "0",
            "ResponseCode": "000"
        },
        "fielda": "00000000000000000000000000NU1234567830121456789012345600000000000000000CL0000000",
        "fieldB": "000000000003000000",
        "fieldP": "1",
        "fieldQ": "0000000000000000",
        "fieldS": "1234567830",
        "fieldW": "0161000000CR   0000",
        "fieldf": "04",
        "fieldb": "4114AAD7B8C63081",
        "fielde": "27",
        "fieldd": "597042320685",
        "fieldh": "0013353351",
        "fieldq": ";5491621004412803=22082061721513240035?",
        "fieldt": "98   1640008933  1640008933       1.1.0           ",
        "field6": {
            "field6subfieldE": "051",
            "field6subfieldI": "152",
            "field6subfieldO": "01801522304126B05ECBD01AA386C3900009D1803E6500040048000001520000000300000000000000000110A04003220000000000000000000000FF",
            "field6subfieldP": "0101244203000002          6048C840008933RA0000000041010",
            "field6subfieldq": "015491621004412803",
            "field6subfieldT": "FFFF00000000512000D4000",
            "field6subfieldX": "100000400282"
        },
        "field9": {
            "field9subfieldA": "1EL20252627            VI01   6MC012367DC     6AX1    6OTTP06TR1 TE0 TM0 TC0 TD0 TJ0 TH0 TA00T90 ",
            "field9subfieldB": "81005300",
            "field9subfieldC": "1000",
            "field9subfieldY": "05AB011",
            "field9subfieldZ": ""
        }
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