// Cargar variables de entorno
require('dotenv').config();

const express = require('express'); // recomendado usar 4.x
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult, param, query } = require('express-validator');
const { Parser } = require('json2csv');
const crypto = require('crypto');                 // <-- para tokens de reset
const nodemailer = require('nodemailer');         // <-- opcional (SMTP)

const app = express();
const PORT = process.env.PORT || 3001;

/* =========================================================
   Seguridad básica y parsing
========================================================= */
const allowedOrigin = process.env.CORS_ORIGIN || 'http://localhost:3000';
app.use(cors({ origin: allowedOrigin }));
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

// Rate limit para login y recuperación
app.use('/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
const forgotLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
app.use('/forgot-password', forgotLimiter);
app.use('/reset-password', forgotLimiter);

/* =========================================================
   Conexión MySQL
========================================================= */
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'sistema_energia_eolica',
  multipleStatements: false
});

db.connect((err) => {
  if (err) {
    console.error('❌ Error al conectar con la BD:', err);
  } else {
    console.log('✅ Conectado a MySQL (sistema_energia_eolica)');
  }
});

/* =========================================================
   Mailer opcional (SMTP). Si no hay .env, se usa consola
========================================================= */
let mailer = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  console.log('📧 SMTP habilitado para recuperación de contraseña');
} else {
  console.log('ℹ️ SMTP no configurado. Los enlaces de reset se imprimirán en consola.');
}

/* =========================================================
   Helpers de autenticación
========================================================= */
function firmarToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES || '4h'
  });
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const [, token] = auth.split(' ');
  if (!token) {
    res.status(401).json({ error: 'Token faltante' });
    return;
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { cuenta_id, rol }
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function requireRole(...rolesPermitidos) {
  return (req, res, next) => {
    if (!req.user) {
      res.status(401).json({ error: 'No autenticado' });
      return;
    }
    const rolUser = (req.user.rol || '').toLowerCase().trim();
    const ok = rolesPermitidos.map(r => r.toLowerCase().trim()).includes(rolUser);
    if (!ok) {
      res.status(403).json({ error: 'Sin permisos' });
      return;
    }
    next();
  };
}

/* =========================================================
   /login — bcrypt + JWT + bloqueo + bitácora
========================================================= */
app.post(
  '/login',
  [
    body('usuario').isString().trim().isLength({ min: 3, max: 120 }),
    body('contrasena').isString().isLength({ min: 3, max: 100 })
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ success: false, errores: errors.array() });
      return;
    }

    const { usuario, contrasena } = req.body;
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().slice(0, 45);
    const agente = (req.headers['user-agent'] || '').slice(0, 255);

    const sql = `
      SELECT 
        c.id_cuenta,
        c.usuario,
        c.contrasena AS hash,
        c.intentos_fallidos,
        c.bloqueado_hasta,
        r.nombre_rol
      FROM cuentas c
      JOIN usuarios u ON u.cuenta_id = c.id_cuenta
      JOIN roles r    ON r.id_rol    = u.rol_id
      WHERE c.usuario = ?
      LIMIT 1
    `;

    db.query(sql, [usuario], async (err, rows) => {
      if (err) {
        res.status(500).json({ success: false, mensaje: 'Error de servidor' });
        return;
      }

      // Usuario NO existe
      if (!rows || rows.length === 0) {
        db.query(
          'INSERT INTO bitacora_accesos (usuario_intento, ip, agente_usuario, exito, motivo) VALUES (?, ?, ?, 0, ?)',
          [usuario, ip, agente, 'usuario_no_encontrado']
        );
        res.status(401).json({ success: false, mensaje: 'Usuario o contraseña incorrectos' });
        return;
      }

      const u = rows[0];

      // ¿Cuenta bloqueada?
      if (u.bloqueado_hasta && new Date(u.bloqueado_hasta) > new Date()) {
        db.query(
          'INSERT INTO bitacora_accesos (cuenta_id, usuario_intento, ip, agente_usuario, exito, motivo) VALUES (?, ?, ?, ?, 0, ?)',
          [u.id_cuenta, u.usuario, ip, agente, 'bloqueado']
        );
        res.status(423).json({ success: false, mensaje: 'Cuenta bloqueada temporalmente. Intente más tarde.' });
        return;
      }

      // Verificar contraseña
      const ok = await bcrypt.compare(contrasena, u.hash);
      if (!ok) {
        const fails = (u.intentos_fallidos || 0) + 1;

        if (fails >= 5) {
          // Bloquear 15 minutos
          db.query(
            'UPDATE cuentas SET intentos_fallidos = 0, bloqueado_hasta = DATE_ADD(NOW(), INTERVAL 15 MINUTE) WHERE id_cuenta = ?',
            [u.id_cuenta]
          );
        } else {
          db.query('UPDATE cuentas SET intentos_fallidos = ? WHERE id_cuenta = ?', [fails, u.id_cuenta]);
        }

        db.query(
          'INSERT INTO bitacora_accesos (cuenta_id, usuario_intento, ip, agente_usuario, exito, motivo) VALUES (?, ?, ?, ?, 0, ?)',
          [u.id_cuenta, u.usuario, ip, agente, 'contrasena_incorrecta']
        );

        res.status(401).json({
          success: false,
          mensaje: fails >= 5
            ? 'Demasiados intentos. Cuenta bloqueada 15 minutos.'
            : 'Usuario o contraseña incorrectos'
        });
        return;
      }

      // Éxito: resetear intentos, limpiar bloqueo, actualizar último acceso
      db.query('UPDATE cuentas SET intentos_fallidos = 0, bloqueado_hasta = NULL, ultimo_acceso = NOW() WHERE id_cuenta = ?', [u.id_cuenta]);

      db.query(
        'INSERT INTO bitacora_accesos (cuenta_id, usuario_intento, ip, agente_usuario, exito, motivo) VALUES (?, ?, ?, ?, 1, ?)',
        [u.id_cuenta, u.usuario, ip, agente, 'login_ok']
      );

      const rol = (u.nombre_rol || '').toLowerCase().trim(); // 'administrador' | 'usuario'
      const token = firmarToken({ cuenta_id: u.id_cuenta, rol });

      res.json({ success: true, token, rol, usuario: u.usuario });
    });
  }
);

// Verificar sesión
app.get('/me', requireAuth, (req, res) => {
  res.json({ cuenta_id: req.user.cuenta_id, rol: req.user.rol });
});

// Detalle del usuario logueado
app.get('/me-detalle', requireAuth, (req, res) => {
  const cuentaId = req.user.cuenta_id;

  const sql = `
    SELECT 
      c.id_cuenta,
      c.usuario AS login,
      r.nombre_rol AS rol,
      u.id_usuario,
      u.nombres,
      u.primer_apellido,
      u.segundo_apellido,
      u.telefono,
      u.direccion,
      u.fecha_nacimiento,
      u.email
    FROM usuarios u
    JOIN cuentas c ON c.id_cuenta = u.cuenta_id
    JOIN roles r   ON r.id_rol    = u.rol_id
    WHERE u.cuenta_id = ?
    LIMIT 1
  `;

  db.query(sql, [cuentaId], (err, rows) => {
    if (err) { res.status(500).json({ mensaje: 'Error en servidor' }); return; }
    if (!rows || rows.length === 0) { res.status(404).json({ mensaje: 'No encontrado' }); return; }

    const u = rows[0];
    const nombre_completo = [u.nombres, u.primer_apellido, u.segundo_apellido].filter(Boolean).join(' ').trim();

    res.json({
      cuenta_id: u.id_cuenta,
      id_usuario: u.id_usuario,
      login: u.login,
      rol: (u.rol || '').toLowerCase(),
      nombres: u.nombres,
      primer_apellido: u.primer_apellido,
      segundo_apellido: u.segundo_apellido,
      telefono: u.telefono,
      direccion: u.direccion,
      fecha_nacimiento: u.fecha_nacimiento,
      email: u.email || null,
      nombre_completo
    });
  });
});

/* =========================================================
   Recuperación de contraseña (Forgot / Reset)
========================================================= */

// Solicitar enlace de recuperación (no revela si existe o no)
app.post(
  '/forgot-password',
  [ body('usuario').isString().trim().isLength({ min: 3, max: 120 }) ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errores: errors.array() });

    const { usuario } = req.body;

    const sql = `
      SELECT c.id_cuenta, c.usuario, u.email
      FROM cuentas c
      JOIN usuarios u ON u.cuenta_id = c.id_cuenta
      WHERE c.usuario = ?
      LIMIT 1
    `;
    db.query(sql, [usuario], (err, rows) => {
      if (err) return res.status(500).json({ mensaje: 'Error en servidor' });

      // Respuesta genérica SIEMPRE
      const generic = { mensaje: 'Si el usuario existe, te enviaremos un enlace de recuperación.' };
      if (!rows || rows.length === 0) return res.json(generic);

      const u = rows[0];
      const token = crypto.randomBytes(20).toString('hex');
      const upd = `UPDATE cuentas SET reset_token=?, reset_expires=DATE_ADD(NOW(), INTERVAL 15 MINUTE) WHERE id_cuenta=?`;
      db.query(upd, [token, u.id_cuenta], async (e2) => {
        if (e2) return res.status(500).json({ mensaje: 'No se pudo generar el token' });

        const base = process.env.APP_BASE_URL || 'http://localhost:3000';
        const resetUrl = `${base}/reset-password/${token}`;

        const destino = u.email || u.usuario; // usa email del perfil o el login (si es email)
        if (mailer && destino) {
          try {
            await mailer.sendMail({
              from: `"Sistema Eólico" <${process.env.SMTP_USER}>`,
              to: destino,
              subject: 'Recupera tu contraseña',
              html: `
                <p>Hola ${u.usuario},</p>
                <p>Usa este enlace para restablecer tu contraseña (expira en 15 minutos):</p>
                <p><a href="${resetUrl}">${resetUrl}</a></p>
              `,
            });
          } catch (e3) {
            console.log('[RESET LINK]', resetUrl);
          }
        } else {
          // Sin SMTP: imprime el enlace en consola
          console.log('[RESET LINK]', resetUrl);
        }

        return res.json(generic);
      });
    });
  }
);

// Restablecer contraseña con token
app.post(
  '/reset-password',
  [
    body('token').isString().trim().isLength({ min: 10 }),
    body('nueva_contrasena').isString().isLength({ min: 8, max: 100 }), // min 8 en backend también
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errores: errors.array() });

    const { token, nueva_contrasena } = req.body;

    const find = `
      SELECT id_cuenta
      FROM cuentas
      WHERE reset_token = ?
        AND reset_expires IS NOT NULL
        AND reset_expires > NOW()
      LIMIT 1
    `;
    db.query(find, [token], async (err, rows) => {
      if (err) return res.status(500).json({ mensaje: 'Error en servidor' });
      if (!rows || rows.length === 0) return res.status(400).json({ mensaje: 'Token inválido o expirado' });

      const idCuenta = rows[0].id_cuenta;
      const hash = await bcrypt.hash(nueva_contrasena, 12);

      const upd = `
        UPDATE cuentas
        SET contrasena = ?, reset_token=NULL, reset_expires=NULL
        WHERE id_cuenta = ?
      `;
      db.query(upd, [hash, idCuenta], (e2) => {
        if (e2) return res.status(500).json({ mensaje: 'No se pudo actualizar la contraseña' });
        return res.json({ mensaje: 'Contraseña actualizada correctamente' });
      });
    });
  }
);

/* =========================================================
   USUARIOS — admin (GET/POST/PUT/DELETE)
========================================================= */

// Listar usuarios (admin) con cuenta y rol
// Listar usuarios (admin) con filtro de búsqueda opcional
app.get('/usuarios', requireAuth, requireRole('administrador'), (req, res) => {
  const busqueda = (req.query.busqueda || '').toString().trim();

  let sql = `
    SELECT 
      u.*,
      c.usuario,
      r.nombre_rol
    FROM usuarios u
    JOIN cuentas c ON c.id_cuenta = u.cuenta_id
    JOIN roles r   ON r.id_rol    = u.rol_id
  `;
  const params = [];

  if (busqueda) {
    sql += `
      WHERE 
        u.id_usuario LIKE ?
        OR c.usuario LIKE ?
        OR u.nombres LIKE ?
        OR u.primer_apellido LIKE ?
        OR u.segundo_apellido LIKE ?
        OR u.ci LIKE ?
        OR u.telefono LIKE ?
        OR u.direccion LIKE ?
    `;
    const like = `%${busqueda}%`;
    params.push(like, like, like, like, like, like, like, like);
  }

  sql += ' ORDER BY u.id_usuario ASC';

  db.query(sql, params, (err, result) => {
    if (err) { res.status(500).send(err); return; }
    res.json(result);
  });
});


// Crear usuario (admin)
app.post(
  '/usuarios',
  requireAuth,
  requireRole('administrador'),
  [
    // ahora el login debe ser email
    body('usuario').isEmail().withMessage('usuario debe ser un correo válido').isLength({ max: 120 }),
    // política mínima backend
    body('contrasena').isString().isLength({ min: 8, max: 100 }),
    body('rol').isString().trim().isIn(['administrador', 'usuario']),
    body('nombres').optional().isString().trim().isLength({ max: 60 }),
    body('primer_apellido').optional().isString().trim().isLength({ max: 60 }),
    body('segundo_apellido').optional().isString().trim().isLength({ max: 60 }),
    body('ci').optional().isString().trim().isLength({ max: 20 }),
    body('telefono').optional().isString().trim().isLength({ max: 25 }),
    body('direccion').optional().isString().trim().isLength({ max: 255 }),
    body('fecha_nacimiento').optional().isISO8601().toDate(),
    body('email').optional().isEmail().isLength({ max: 120 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errores: errors.array() }); return; }

    const {
      usuario, contrasena, rol,
      nombres, primer_apellido, segundo_apellido,
      ci, telefono, direccion, fecha_nacimiento, email
    } = req.body;

    // 1) Rol -> id_rol
    db.query('SELECT id_rol FROM roles WHERE nombre_rol = ? LIMIT 1', [rol], async (e1, rRol) => {
      if (e1) { res.status(500).json({ mensaje: 'Error buscando rol' }); return; }
      if (!rRol.length) { res.status(400).json({ mensaje: 'Rol inválido' }); return; }
      const rol_id = rRol[0].id_rol;

      // 2) Usuario único
      db.query('SELECT id_cuenta FROM cuentas WHERE usuario = ? LIMIT 1', [usuario], async (e2, rDup) => {
        if (e2) { res.status(500).json({ mensaje: 'Error verificando usuario' }); return; }
        if (rDup.length) { res.status(409).json({ mensaje: 'El usuario ya existe' }); return; }

        // 3) Hash y guardar
        const hash = await bcrypt.hash(contrasena, 12);

        db.beginTransaction((txErr) => {
          if (txErr) { res.status(500).json({ mensaje: 'No se pudo iniciar la transacción' }); return; }

          db.query('INSERT INTO cuentas (usuario, contrasena) VALUES (?, ?)', [usuario, hash], (e3, rCta) => {
            if (e3) { db.rollback(() => {}); res.status(500).json({ mensaje: 'Error creando cuenta' }); return; }

            const cuenta_id = rCta.insertId;
            const sqlU = `
              INSERT INTO usuarios
                (cuenta_id, rol_id, nombres, primer_apellido, segundo_apellido, ci, fecha_nacimiento, telefono, direccion, email)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
            const emailFinal = email || usuario; // si no mandan email de perfil, usa el login
            db.query(sqlU, [
              cuenta_id, rol_id,
              nombres || null, primer_apellido || null, segundo_apellido || null,
              ci || null, fecha_nacimiento || null, telefono || null, direccion || null, emailFinal || null
            ], (e4) => {
              if (e4) { db.rollback(() => {}); res.status(500).json({ mensaje: 'Error creando usuario' }); return; }

              // Auditoría opcional
              const detalle = JSON.stringify({ usuario, rol });
              db.query(
                'INSERT INTO auditoria_usuarios (actor_cuenta_id, accion, objetivo_cuenta_id, detalle) VALUES (?, "CREAR", ?, ?)',
                [req.user.cuenta_id, cuenta_id, detalle],
                (e5) => {
                  if (e5) { db.rollback(() => {}); res.status(500).json({ mensaje: 'Error de auditoría' }); return; }
                  db.commit((cErr) => {
                    if (cErr) { db.rollback(() => res.status(500).json({ mensaje: 'Error al confirmar transacción' })); return; }
                    res.status(201).json({ mensaje: 'Usuario creado correctamente' });
                  });
                }
              );
            });
          });
        });
      });
    });
  }
);

// Actualizar usuario (admin)
app.put(
  '/usuarios/:id',
  requireAuth,
  requireRole('administrador'),
  [
    param('id').isInt({ min: 1 }),
    body('nombres').optional().isString().trim().isLength({ max: 60 }),
    body('primer_apellido').optional().isString().trim().isLength({ max: 60 }),
    body('segundo_apellido').optional().isString().trim().isLength({ max: 60 }),
    body('ci').optional().isString().trim().isLength({ max: 20 }),
    body('telefono').optional().isString().trim().isLength({ max: 25 }),
    body('direccion').optional().isString().trim().isLength({ max: 255 }),
    body('fecha_nacimiento').optional().isISO8601().toDate(),
    body('rol').optional().isString().trim().isIn(['administrador','usuario']),
    body('email').optional().isEmail().isLength({ max: 120 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errores: errors.array() }); return; }

    const { id } = req.params;
    const {
      nombres, primer_apellido, segundo_apellido,
      ci, fecha_nacimiento, telefono, direccion,
      rol, email,
    } = req.body;

    // Si no cambia rol
    if (!rol) {
      const sql = `
        UPDATE usuarios SET 
          nombres = ?, 
          primer_apellido = ?, 
          segundo_apellido = ?, 
          ci = ?, 
          fecha_nacimiento = ?, 
          telefono = ?, 
          direccion = ?,
          email = ?
        WHERE id_usuario = ?
      `;
      db.query(sql, [nombres || null, primer_apellido || null, segundo_apellido || null, ci || null, fecha_nacimiento || null, telefono || null, direccion || null, email || null, id], (err) => {
        if (err) { res.status(500).send(err); return; }
        res.sendStatus(200);
      });
      return;
    }

    // Con cambio de rol
    db.beginTransaction((txErr) => {
      if (txErr) { res.status(500).json({ mensaje: 'No se pudo iniciar la transacción' }); return; }

      db.query('SELECT id_rol FROM roles WHERE nombre_rol = ? LIMIT 1', [rol], (e1, rRol) => {
        if (e1) { db.rollback(() => {}); res.status(500).json({ mensaje: 'Error buscando rol' }); return; }
        if (!rRol.length) { db.rollback(() => {}); res.status(400).json({ mensaje: 'Rol inválido' }); return; }

        const rol_id = rRol[0].id_rol;
        const sql = `
          UPDATE usuarios SET 
            rol_id = ?, 
            nombres = ?, 
            primer_apellido = ?, 
            segundo_apellido = ?, 
            ci = ?, 
            fecha_nacimiento = ?, 
            telefono = ?, 
            direccion = ?,
            email = ?
          WHERE id_usuario = ?
        `;
        db.query(sql, [rol_id, nombres || null, primer_apellido || null, segundo_apellido || null, ci || null, fecha_nacimiento || null, telefono || null, direccion || null, email || null, id], (e2) => {
          if (e2) { db.rollback(() => {}); res.status(500).json({ mensaje: 'Error al actualizar usuario' }); return; }

          const detalle = JSON.stringify({ id_usuario: id, nuevo_rol: rol });
          db.query('INSERT INTO auditoria_usuarios (actor_cuenta_id, accion, objetivo_cuenta_id, detalle) VALUES (?, "ACTUALIZAR", NULL, ?)', [req.user.cuenta_id, detalle], (e3) => {
            if (e3) { db.rollback(() => {}); res.status(500).json({ mensaje: 'Error de auditoría' }); return; }
            db.commit((cErr) => {
              if (cErr) { db.rollback(() => res.status(500).json({ mensaje: 'Error al confirmar transacción' })); return; }
              res.sendStatus(200);
            });
          });
        });
      });
    });
  }
);

// Eliminar usuario (admin)
app.delete('/usuarios/:id', requireAuth, requireRole('administrador'), [param('id').isInt({ min: 1 })], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) { res.status(400).json({ errores: errors.array() }); return; }

  const { id } = req.params;
  db.query('DELETE FROM usuarios WHERE id_usuario = ?', [id], (err) => {
    if (err) { res.status(500).send(err); return; }
    res.sendStatus(200);
  });
});

/* =========================================================
   Resumen / Alertas
========================================================= */

// Últimas 100 lecturas (admin ve todo; usuario solo lo suyo)
app.get('/resumen', requireAuth, (req, res) => {
  const esAdmin = (req.user.rol || '').toLowerCase() === 'administrador';
  const userId = req.query.userId ? Number(req.query.userId) : null;

  // NO admin: solo su propia data
  if (!esAdmin) {
    const sql = `
      SELECT lr.*
      FROM lecturas_resumen lr
      JOIN usuarios u ON u.id_usuario = lr.usuario_id
      WHERE u.cuenta_id = ?
      ORDER BY lr.fecha_lectura DESC
      LIMIT 100
    `;
    db.query(sql, [req.user.cuenta_id], (err, rows) => {
      if (err) { res.status(500).send('Error en servidor'); return; }
      res.json(rows);
    });
    return;
  }

  // Admin con filtro userId
  if (Number.isInteger(userId) && userId > 0) {
    const sqlAdmFiltrado = `
      SELECT * 
      FROM lecturas_resumen 
      WHERE usuario_id = ?
      ORDER BY fecha_lectura DESC
      LIMIT 100
    `;
    db.query(sqlAdmFiltrado, [userId], (err, rows) => {
      if (err) { res.status(500).send('Error en servidor'); return; }
      res.json(rows);
    });
    return;
  }

  // Admin sin filtro -> todo
  db.query('SELECT * FROM lecturas_resumen ORDER BY fecha_lectura DESC LIMIT 100', (err, rows) => {
    if (err) { res.status(500).send('Error en servidor'); return; }
    res.json(rows);
  });
});

// Últimas 10 lecturas (para alertas simples)
app.get('/alertas', requireAuth, (req, res) => {
  const esAdmin = (req.user.rol || '').toLowerCase() === 'administrador';
  const where = `( (lr.bateria IS NOT NULL AND lr.bateria < 20)
                OR (lr.voltaje IS NOT NULL AND lr.voltaje < 10) )`;

  if (!esAdmin) {
    const sql = `
      SELECT lr.voltaje, lr.bateria, lr.consumo, lr.fecha_lectura
      FROM lecturas_resumen lr
      JOIN usuarios u ON u.id_usuario = lr.usuario_id
      WHERE u.cuenta_id = ? AND ${where}
      ORDER BY lr.fecha_lectura DESC
      LIMIT 10
    `;
    db.query(sql, [req.user.cuenta_id], (err, rows) => {
      if (err) { res.status(500).send('Error en servidor'); return; }
      res.json(rows);
    });
    return;
  }

  const sqlAdmin = `
    SELECT voltaje, bateria, consumo, fecha_lectura
    FROM lecturas_resumen lr
    WHERE ${where}
    ORDER BY fecha_lectura DESC
    LIMIT 10
  `;
  db.query(sqlAdmin, (err, rows) => {
    if (err) { res.status(500).send('Error en servidor'); return; }
    res.json(rows);
  });
});

// Helper para filtros de alertas
function buildAlertWhereClause(onlyAlertas, alias = 'lr') {
  if (!onlyAlertas) return { clause: '', params: [] };
  const VOLTAJE_ALTO = 15;  // V
  const BATERIA_BAJA = 20;  // %
  const CONSUMO_ALTO = 80;  // W
  const clause = ` AND ( ${alias}.voltaje > ? OR ${alias}.bateria < ? OR ${alias}.consumo > ? ) `;
  const params = [VOLTAJE_ALTO, BATERIA_BAJA, CONSUMO_ALTO];
  return { clause, params };
}

// GET /alertas/rango — usuario actual
app.get('/alertas/rango',
  requireAuth,
  [
    query('desde').isISO8601().withMessage('desde inválido'),
    query('hasta').isISO8601().withMessage('hasta inválido'),
    query('soloAlertas').optional().isIn(['0','1','true','false']),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errores: errors.array() }); return; }

    const { desde, hasta, soloAlertas } = req.query;
    const cuentaId = req.user.cuenta_id;
    const onlyAlertas = soloAlertas === '1' || soloAlertas === 'true';
    const alertFilter = buildAlertWhereClause(onlyAlertas, 'lr');

    const sql = `
      SELECT lr.*
      FROM lecturas_resumen lr
      JOIN usuarios u ON u.id_usuario = lr.usuario_id
      WHERE u.cuenta_id = ?
        AND lr.fecha_lectura BETWEEN CONCAT(?, ' 00:00:00') AND CONCAT(?, ' 23:59:59')
      ${alertFilter.clause}
      ORDER BY lr.fecha_lectura ASC
    `;
    const params = [cuentaId, desde, hasta, ...alertFilter.params];

    db.query(sql, params, (err, rows) => {
      if (err) { console.error(err); res.status(500).json({ mensaje: 'Error en servidor' }); return; }
      res.json(rows || []);
    });
  }
);

// GET /alertas/admin-rango — admin
app.get('/alertas/admin-rango',
  requireAuth,
  requireRole('administrador'),
  [
    query('desde').isISO8601().withMessage('desde inválido'),
    query('hasta').isISO8601().withMessage('hasta inválido'),
    query('soloAlertas').optional().isIn(['0','1','true','false']),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errores: errors.array() }); return; }

    const { desde, hasta, soloAlertas } = req.query;
    const onlyAlertas = soloAlertas === '1' || soloAlertas === 'true';
    const alertFilter = buildAlertWhereClause(onlyAlertas, 'lr');

    const sql = `
      SELECT 
        lr.id_lectura,
        lr.usuario_id,
        lr.voltaje,
        lr.bateria,
        lr.consumo,
        lr.fecha_lectura,
        c.usuario       AS login,
        r.nombre_rol    AS rol,
        u.nombres,
        u.primer_apellido,
        u.segundo_apellido
      FROM lecturas_resumen lr
      JOIN usuarios u ON u.id_usuario = lr.usuario_id
      JOIN cuentas c  ON c.id_cuenta  = u.cuenta_id
      JOIN roles r    ON r.id_rol     = u.rol_id
      WHERE lr.fecha_lectura BETWEEN CONCAT(?, ' 00:00:00') AND CONCAT(?, ' 23:59:59')
      ${alertFilter.clause}
      ORDER BY lr.fecha_lectura ASC
    `;
    const params = [desde, hasta, ...alertFilter.params];

    db.query(sql, params, (err, rows) => {
      if (err) { console.error(err); res.status(500).json({ mensaje: 'Error en servidor' }); return; }
      res.json(rows || []);
    });
  }
);

// GET /resumen/rango — usuario actual
app.get('/resumen/rango',
  requireAuth,
  [
    query('desde').isISO8601().withMessage('desde inválido'),
    query('hasta').isISO8601().withMessage('hasta inválido'),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errores: errors.array() }); return; }

    const { desde, hasta } = req.query;
    const cuentaId = req.user.cuenta_id;

    const sql = `
      SELECT lr.*
      FROM lecturas_resumen lr
      JOIN usuarios u ON u.id_usuario = lr.usuario_id
      WHERE u.cuenta_id = ?
        AND lr.fecha_lectura BETWEEN CONCAT(?, ' 00:00:00') AND CONCAT(?, ' 23:59:59')
      ORDER BY lr.fecha_lectura ASC
    `;
    db.query(sql, [cuentaId, desde, hasta], (err, rows) => {
      if (err) { console.error(err); res.status(500).json({ mensaje: 'Error en servidor' }); return; }
      res.json(rows || []);
    });
  }
);

// GET /resumen/admin-rango — admin
app.get('/resumen/admin-rango',
  requireAuth,
  requireRole('administrador'),
  [
    query('desde').isISO8601().withMessage('desde inválido'),
    query('hasta').isISO8601().withMessage('hasta inválido'),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errores: errors.array() }); return; }

    const { desde, hasta } = req.query;

    const sql = `
      SELECT 
        lr.id_lectura,
        lr.usuario_id,
        lr.voltaje,
        lr.bateria,
        lr.consumo,
        lr.fecha_lectura,
        c.usuario       AS login,
        r.nombre_rol    AS rol,
        u.nombres,
        u.primer_apellido,
        u.segundo_apellido
      FROM lecturas_resumen lr
      JOIN usuarios u ON u.id_usuario = lr.usuario_id
      JOIN cuentas c  ON c.id_cuenta  = u.cuenta_id
      JOIN roles r    ON r.id_rol     = u.rol_id
      WHERE lr.fecha_lectura BETWEEN CONCAT(?, ' 00:00:00') AND CONCAT(?, ' 23:59:59')
      ORDER BY lr.fecha_lectura ASC
    `;
    db.query(sql, [desde, hasta], (err, rows) => {
      if (err) { console.error(err); res.status(500).json({ mensaje: 'Error en servidor' }); return; }
      res.json(rows || []);
    });
  }
);

/* =========================================================
   Reporte CSV (usuarios) — solo admin
========================================================= */
app.get('/reporte-usuarios', requireAuth, requireRole('administrador'), (req, res) => {
  db.query('SELECT nombres, primer_apellido, segundo_apellido, ci, fecha_nacimiento, telefono, direccion, email FROM usuarios', (err, results) => {
    if (err) { res.status(500).send('Error en servidor'); return; }
    const fields = ['nombres','primer_apellido','segundo_apellido','ci','fecha_nacimiento','telefono','direccion','email'];
    const csv = new Parser({ fields }).parse(results);
    res.header('Content-Type', 'text/csv');
    res.attachment('reporte_usuarios.csv');
    res.send(csv);
  });
});

/* =========================================================
   Iniciar servidor
========================================================= */
app.listen(PORT, () => {
  console.log(`🚀 Backend escuchando en http://localhost:${PORT}`);
});
