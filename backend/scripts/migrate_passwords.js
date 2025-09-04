// backend/scripts/migrate_passwords.js
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

(async () => {
  let conn;
  try {
    // Conexión
    conn = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASS || '',
      database: process.env.DB_NAME || 'sistemaenergia1'
    });
    console.log('Conectado a MySQL');

    // Leer todos los logins
    const [rows] = await conn.execute('SELECT id, usuario, password FROM login');
    for (const row of rows) {
      const { id, password } = row;
      // Si ya es bcrypt ($2a/$2b/$2y), saltar
      if (/^\$2[aby]\$/.test(password)) {
        console.log(`(skip) login.id=${id} ya está hasheado`);
        continue;
      }

      const hash = await bcrypt.hash(password, 12);
      await conn.execute('UPDATE login SET password = ? WHERE id = ?', [hash, id]);
      console.log(`✔ Hasheada password para login.id=${id}`);
    }

    console.log('Migración completa.');
  } catch (e) {
    console.error('Error en migración:', e.message);
  } finally {
    if (conn) await conn.end();
  }
})();
