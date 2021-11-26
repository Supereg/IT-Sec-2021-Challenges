const jwt = require("jsonwebtoken");
const fs = require("fs");

const TOKEN_EXPIRY = "1h";
const SECRET_KEY = fs.readFileSync("secret.key");

const USER_ROLE = "user";
const SUPERVISOR_ROLE = "supervisor";
const ADMIN_ROLE = "admin";

generateToken = function (claims) {
  const options = {algorithm: "HS256"};
  if (typeof claims === 'object')
    options.expiresIn = TOKEN_EXPIRY;
  return jwt.sign(claims, SECRET_KEY, options);
}

validateToken = function(token) {
  try {
    const payload = jwt.verify(token, SECRET_KEY, {algorithms: ["HS256"]});
    return {valid: true, payload: payload};
  } catch (error) {
    return {valid: false, error: error};
  }
}

extractBearer = function(req) {
  if (!req.headers.authorization)
    return {valid: false, error: "Not authenticated"};
  const parts = req.headers.authorization.split(" ");
  if (parts[0] !== "Bearer")
    return {valid: false, error: "Incorrect authorization type (must be Bearer)"};
  return {valid: true, token: parts[1]};
}

requireAuth = function(req, res, roles = [USER_ROLE, SUPERVISOR_ROLE, ADMIN_ROLE], bypassUsers = []) {
  const bearer = extractBearer(req);
  if (!bearer.valid) {
    res.status(401).json({"error": bearer.error});
    return;
  }
  const result = validateToken(bearer.token);
  if (!result.valid) {
    res.status(401).json({"error": result.error.message});
    return;
  }
  if (result.payload.auth === undefined) {
    res.status(401).json({"error": "No authorization claim in token"});
    return;
  }
  if (!Array.isArray(roles))
    roles = [roles];
  if (!Array.isArray(bypassUsers))
    bypassUsers = [bypassUsers];
  if (!roles.includes(result.payload.auth) && !bypassUsers.includes(result.payload.sub)) {
    res.status(401).json({"error": "Insufficient privileges"});
    return;
  }
  return result.payload;
}

module.exports = {
  generateToken,
  validateToken,
  extractBearer,
  requireAuth,
  USER_ROLE,
  SUPERVISOR_ROLE,
  ADMIN_ROLE,
}
