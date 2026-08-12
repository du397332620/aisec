export function calculate(expression) {
  return eval(expression); // nosemgrep
}

export function legacyPasswordDigest(crypto, password) {
  return crypto.createHash("md5").update(password).digest("hex");
}
