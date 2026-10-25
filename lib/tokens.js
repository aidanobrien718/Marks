const jwt = require("jsonwebtoken");

// The signing key must come from the environment and must not be the public
// placeholder that shipped in the repo/.env.example. A hardcoded or guessable
// secret lets anyone mint their own token (including role:"ta"), so refuse to
// start without a real one instead of silently signing with a known key.
const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET === "marks-dev-secret") {
  throw new Error(
    "JWT_SECRET must be set to a strong, non-default value. " +
      "Refusing to start with a missing or publicly-known signing key."
  );
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role
    },
    SECRET,
    { algorithm: "HS256", expiresIn: "7d" }
  );
}

function readToken(header) {
  if (!header || !header.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  try {
    // Pin the algorithm so a token cannot ask to be verified a different way.
    return jwt.verify(token, SECRET, { algorithms: ["HS256"] });
  } catch {
    return null;
  }
}

module.exports = { SECRET, signToken, readToken };
