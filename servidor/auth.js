
const { createRemoteJWKSet, jwtVerify } = require('jose');
const config = require('./config');

const issuer = `${config.KEYCLOAK_URL.replace(/\/$/, '')}/realms/${config.KEYCLOAK_REALM}`;

const JWKS = createRemoteJWKSet(
  new URL(`${issuer}/protocol/openid-connect/certs`)
);

async function requireAuth(req, res, next) {
  if (!config.AUTH_ENABLED) {
    return next();
  }

  const authorization = req.headers.authorization || '';
  const match = /^Bearer (.+)$/i.exec(authorization);

  if (!match) {
    return res.status(401).json({
      error: 'Token de autenticación requerido'
    });
  }

  try {
    const { payload } = await jwtVerify(match[1], JWKS, {
      issuer,
      algorithms: ['RS256']
      // Agregar audience cuando se configure el cliente de Keycloak.
    });

    req.usuario = payload;
    return next();
  } catch (error) {
    return res.status(401).json({
      error: 'Token inválido o expirado'
    });
  }
}

module.exports = { requireAuth };
