require('dotenv').config()
const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const { Pool } = require('pg')

const app = express()
const port = process.env.PORT || 3000
const SECRET_KEY = process.env.SECRET_KEY || 'tu_clave_secreta'

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'softjobs',
  password: '18211238-a3163486',
  port: 3163,
  allowExitOnIdle: true
})

app.use(express.json())

app.post('/usuarios', async (req, res) => {
  const { email, password, rol, lenguage } = req.body
  const hashedPassword = await bcrypt.hash(password, 10)
  try {
    const result = await pool.query(
      'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *',
      [email, hashedPassword, rol, lenguage]
    )
    res.status(201).json(result.rows[0])
  } catch (error) {
    res.status(400).json({ error: error.message })
  }
})

app.post('/login', async (req, res) => {
  const { email, password } = req.body
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email])
    const user = result.rows[0]
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' })
      res.json({ token })
    } else {
      res.status(401).json({ message: 'Credenciales incorrectas' })
    }
  } catch (error) {
    res.status(400).json({ error: error.message })
  }
})

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(403).json({ message: 'Token requerido' })
  jwt.verify(token, SECRET_KEY, (error, decoded) => {
    if (error) return res.status(401).json({ message: 'Token inválido' })
    req.email = decoded.email
    next()
  })
}

app.get('/usuarios', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.email])
    const user = result.rows[0]
    if (user) {
      res.json(user)
    } else {
      res.status(404).json({ message: 'Usuario no encontrado' })
    }
  } catch (error) {
    res.status(400).json({ error: error.message })
  }
})

app.use((req, res, next) => {
  console.log(`Consulta: ${req.method} ${req.url}`)
  next()
})
app.use((error, req, res, next) => {
  console.error(error)
  res.status(500).json({ message: 'Error interno del servidor' })
})

app.listen(port, () => {
  console.log(`Servidor ejecutándose en http://localhost:${port}`)
})
