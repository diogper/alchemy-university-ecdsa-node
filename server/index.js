const express = require("express");
const app = express();
const cors = require("cors");
const port = 3042;

const crypto = require("./scripts/crypto");
const { toHex, utf8ToBytes, bytesToHex } = require("ethereum-cryptography/utils");
const keccak256 = require("ethereum-cryptography/keccak").keccak256;

app.use(cors());
app.use(express.json());

const balances = {};
const accounts = {};
const transactions = {};

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  const { sender, recipient, amount, signature, nonce } = req.body;

  setInitialBalance(sender);
  setInitialBalance(recipient);

  let sigHex = signature.split(',')[0];
  let sigRec = parseInt(signature.split(',')[1]);
  let msgHash = keccak256(utf8ToBytes(sender+recipient+amount+nonce));

  if(!crypto.validateSignature(sigHex,sigRec, msgHash, sender)){
    res.status(400).send({ message: "Invalid Signature for Sender!" });
  } else if(parseInt(nonce) !== transactions[sender]) {
    res.status(400).send({ message: "Invalid Nonce!" });
  } else if (balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" });
  } else {
    balances[sender] -= amount;
    balances[recipient] += amount;
    transactions[sender]+=1;
    res.send({ balance: balances[sender] });
  }
});

app.listen(port, () => {
  console.log("[!] Generating accounts...")
  let alice = crypto.genPrivateKey();
  accounts[crypto.toHex(alice)]= crypto.toHex(crypto.getPublicKey(alice));
  balances[crypto.getWalletAddr(crypto.getPublicKey(alice))] = 100;
  transactions[crypto.getWalletAddr(crypto.getPublicKey(alice))] = 0;


  let bob = crypto.genPrivateKey();
  accounts[crypto.toHex(bob)]= crypto.toHex(crypto.getPublicKey(bob));
  balances[crypto.getWalletAddr(crypto.getPublicKey(bob))] = 50;
  transactions[crypto.getWalletAddr(crypto.getPublicKey(bob))] = 0;

  let john = crypto.genPrivateKey();
  accounts[crypto.toHex(john)]= crypto.toHex(crypto.getPublicKey(john));
  balances[crypto.getWalletAddr(crypto.getPublicKey(john))] = 75;
  transactions[crypto.getWalletAddr(crypto.getPublicKey(john))] = 0;

  console.log("[+] Accounts: {privateKey:publicKey}");
  console.log(accounts);
  console.log("[+] Balances: {walletAddress:balance}");
  console.log(balances);
  console.log("[+] Signature example from Alice @ "+crypto.getWalletAddr(crypto.getPublicKey(alice)));
  console.log("[+] Signing: Sender="+crypto.getWalletAddr(crypto.getPublicKey(alice))+" Recipient="+ crypto.getWalletAddr(crypto.getPublicKey(bob)) + " Amount: 10 Nonce: 0");
  console.log('[+] Signature Output (sig,recovery): '+ crypto.genSignature(alice,crypto.getWalletAddr(crypto.getPublicKey(alice))+crypto.getWalletAddr(crypto.getPublicKey(bob))+'10'+'0'));
  console.log(`\nListening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
