const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Serve static files (index.html)
app.use(express.static(path.join(__dirname)));

// Postgres Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Inisialisasi Tabel Database
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        id SERIAL PRIMARY KEY,
        license_key VARCHAR(255) UNIQUE NOT NULL,
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Database initialized successfully.');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
}
initDb();

// Endpoint Check License
app.get('/api/check-license', async (req, res) => {
  const { key } = req.query;
  if (!key) return res.json({ valid: false, message: 'License key is required' });

  try {
    const result = await pool.query('SELECT * FROM licenses WHERE license_key = $1 AND status = $2', [key, 'active']);
    if (result.rows.length > 0) {
      res.json({ valid: true, message: 'License active' });
    } else {
      res.json({ valid: false, message: 'License invalid or expired' });
    }
  } catch (err) {
    res.status(500).json({ valid: false, message: 'Server error' });
  }
});

// Endpoint Admin: Add License
app.post('/api/add-license', async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Key required' });

  try {
    await pool.query('INSERT INTO licenses (license_key) VALUES ($1)', [key]);
    res.json({ success: true, message: 'License added' });
  } catch (err) {
    res.status(500).json({ error: 'License already exists or database error' });
  }
});

// Endpoint Admin: Get All Licenses
app.get('/api/licenses', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM licenses ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});