const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');

const app = express();
const port = 3000;
const secretKey = 'your_secret_key';

app.use(express.static(path.join(__dirname, 'src')));
app.use(bodyParser.json({ limit: '10mb' }));

let db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Could not connect to database', err);
  } else {
    console.log('Connected to database');
  }
});

db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY, name TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT, description TEXT, availability TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)");

  const hashedAdminPassword = bcrypt.hashSync('admin', 10);
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?) ON CONFLICT(username) DO NOTHING", ['admin', hashedAdminPassword, 'admin']);
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function authorizeAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  next();
}

app.post('/register', (req, res) => {
  const { username, password, role = 'user' } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, role], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.status(201).json({ id: this.lastID, username, role });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (!user || !bcrypt.compareSync(password, user.password)) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }
    const token = jwt.sign({ username: user.username, role: user.role }, secretKey);
    res.json({ token });
  });
});

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.get('/categories', (req, res) => {
  db.all("SELECT * FROM categories", (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

app.post('/categories', authenticateToken, authorizeAdmin, (req, res) => {
  const { name } = req.body;
  db.run("INSERT INTO categories (name) VALUES (?)", [name], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.status(201).json({ id: this.lastID, name });
  });
});

app.get('/categories/:id', (req, res) => {
  const { id } = req.params;
  db.get("SELECT * FROM categories WHERE id = ?", [id], (err, row) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(row || { message: 'Category not found' });
  });
});

app.put('/categories/:id', authenticateToken, authorizeAdmin, (req, res) => {
  const { id } = req.params;
  const { name } = req.body;
  db.run("UPDATE categories SET name = ? WHERE id = ?", [name, id], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ id, name });
  });
});

app.delete('/categories/:id', authenticateToken, authorizeAdmin, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM categories WHERE id = ?", [id], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ message: 'Category deleted' });
  });
});

app.get('/products', (req, res) => {
  db.all("SELECT * FROM products", (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

app.post('/products', authenticateToken, authorizeAdmin, (req, res) => {
    const { name, price, category, description, availability } = req.body;
  
    console.log('Product creation request:', req.body); // Konsolenlog zur Überprüfung der empfangenen Daten
  
    db.run("INSERT INTO products (name, price, category, description, availability) VALUES (?, ?, ?, ?, ?)", [name, price, category, description, availability], function (err) {
      if (err) {
        console.error('Database error:', err.message); // Konsolenlog bei Datenbankfehlern
        res.status(500).json({ error: err.message });
        return;
      }
      res.status(201).json({ id: this.lastID, name, price, category, description, availability });
    });
  });  

app.get('/products/:id', (req, res) => {
  const { id } = req.params;
  db.get("SELECT * FROM products WHERE id = ?", [id], (err, row) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(row || { message: 'Product not found' });
  });
});

app.put('/products/:id', authenticateToken, authorizeAdmin, (req, res) => {
  const { id } = req.params;
  const { name, price, category, description, availability } = req.body;
  db.run("UPDATE products SET name = ?, price = ?, category = ?, description = ?, availability = ? WHERE id = ?", [name, price, category, description, availability, id], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ id, name, price, category, description, availability });
  });
});

app.delete('/products/:id', authenticateToken, authorizeAdmin, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM products WHERE id = ?", [id], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ message: 'Product deleted' });
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'src', 'Home.html'));
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});