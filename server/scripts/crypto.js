const secp = require("ethereum-cryptography/secp256k1").secp256k1;
const { toHex, utf8ToBytes, bytesToHex } = require("ethereum-cryptography/utils");
const keccak256 = require("ethereum-cryptography/keccak").keccak256;

// const privateKey = secp.utils.randomPrivateKey();
// const publicKey = secp.getPublicKey(privateKey);

function getWalletAddr(pubKey){
    return `0x${toHex(keccak256(pubKey).slice(-20))}`;
}

function genPrivateKey() {
    return secp.utils.randomPrivateKey();
}

function getPublicKey(privKey){
    return secp.getPublicKey(privKey);
}

function hashData(data){
    return keccak256(utf8ToBytes(data));
}

function genSignature(privKey, data){
    let msgHash = keccak256(utf8ToBytes(data));
    return [toHex(secp.sign(msgHash, privKey).toCompactRawBytes()), secp.sign(msgHash, privKey).recovery];
}

function validateSignature(sigHex, sigRec, msgHash,sender){
    let sig = secp.Signature.fromCompact(sigHex);
    sig.recovery = sigRec;
    let pubkey = sig.recoverPublicKey(msgHash).toRawBytes();
    if(sender !== getWalletAddr(pubkey)){
        return false;
    }
    return secp.verify(sig,msgHash,pubkey);
}


module.exports = { getWalletAddr,  genPrivateKey, getPublicKey, toHex, genSignature, hashData,validateSignature};