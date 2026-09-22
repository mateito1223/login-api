const jwt = require('jsonwebtoken');

function verificarToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).send('No se proporcionó un token');
  }

  const token = authHeader.split(' ')[1]; // Formato esperado: "Bearer <token>"

  if (!token) {
    return res.status(401).send('Formato de token inválido');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = decoded; // Guardamos los datos del token para usarlos en la siguiente función
    next(); // Todo bien, deja pasar a la ruta protegida
  } catch (error) {
    return res.status(403).send('Token inválido o expirado');
  }
}

module.exports = verificarToken;