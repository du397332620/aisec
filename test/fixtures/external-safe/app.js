export function calculate(left, right) {
  return Number(left) + Number(right);
}

export function passwordDigest(crypto, password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}
