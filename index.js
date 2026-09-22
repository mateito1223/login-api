const express = require('express');
const pool = require('./db');

const app = express();
const PORT = 3000;

app.get('/', (req, res) => {
  res.send('Servidor funcionando correctamente 🚀');
});

// Ruta de prueba para verificar la conexión a la base de datos
app.get('/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.send(`Conexión exitosa a la base de datos. Hora del servidor: ${result.rows[0].now}`);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al conectar con la base de datos');
  }
});

const bcrypt = require('bcrypt');

app.use(express.json()); // Permite que Express entienda JSON en el body de las peticiones

// Ruta para registrar un nuevo usuario
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Email y contraseña son obligatorios');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at',
      [email, hashedPassword]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(error);

    if (error.code === '23505') {
      return res.status(409).send('Ese email ya está registrado');
    }

    res.status(500).send('Error al registrar el usuario');
  }
});

const jwt = require('jsonwebtoken');

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Email y contraseña son obligatorios');
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(401).send('Credenciales inválidas');
    }

    const user = result.rows[0];

    const passwordValida = await bcrypt.compare(password, user.password);

    if (!passwordValida) {
      return res.status(401).send('Credenciales inválidas');
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ mensaje: 'Login exitoso', token });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al iniciar sesión');
  }
});

const verificarToken = require('./middleware/Auth');

// Ruta protegida: solo accesible con un token válido
app.get('/perfil', verificarToken, (req, res) => {
  res.json({
    mensaje: 'Accediste a una ruta protegida',
    usuario: req.usuario
  });
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});