const fs = require("fs");
const crypto = require("crypto");
const keys = crypto.createDiffieHellman(2048);

fs.writeFileSync("dev/public.pem", keys.generateKeys("base64"));
fs.writeFileSync("dev/private.pem", keys.getPrivateKey("base64"));

