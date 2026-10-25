const jwt = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET || "marks-dev-secret";

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role
    },
    SECRET,
    { expiresIn: "7d" }
  );
}

function readToken(header) {
  if (!header || !header.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  try {
    return jwt.verify(token, SECRET);
  } catch {
    return null;
  }
}

module.exports = { SECRET, signToken, readToken };
