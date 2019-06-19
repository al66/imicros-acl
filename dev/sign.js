const fs = require("fs");
const jwt = require("jsonwebtoken");

let privateKey = fs.readFileSync("dev/private.pem");
//let token = jwt.sign({ foo: "bar" }, privateKey, { algorithm: "HS256"});
let token = jwt.sign({ foo: "bar" }, privateKey);

let decoded = jwt.verify(token, privateKey);
console.log(decoded.foo);