const express = require("express");
const router = express.Router();
const PDFDocument = require("pdfkit");
require("pdfkit-table");
const mysql = require("mysql2");
require("dotenv").config();

// Conexión a MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "sistemaenergia1"
});

// Ruta para generar PDF
router.get("/reporte-usuarios-pdf", (req, res) => {
    const sql = `SELECT nombre, primerApellido, segundoApellido, CedulaIdentidad, fechaNacimiento, telefono, Direccion FROM usuarios`;
  
    db.query(sql, (err, usuarios) => {
      if (err) {
        console.error("Error al obtener usuarios:", err);
        return res.status(500).send("Error al generar PDF");
      }
  
      console.log("Usuarios obtenidos:", usuarios); // 👈 Verifica esto
  
      const doc = new PDFDocument({ margin: 30, size: "A4" });
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", "attachment; filename=reporte_usuarios.pdf");
      doc.pipe(res);
  
      doc.fontSize(18).text("REPORTE DE USUARIOS", { align: "center" });
      doc.moveDown(1);
  
      if (usuarios.length === 0) {
        doc.text("No hay usuarios registrados.", { align: "center" });
      } else {
        const table = {
          headers: [
            { label: "Nombre", property: "nombre", width: 70 },
            { label: "Apellidos", property: "apellidos", width: 100 },
            { label: "C.I.", property: "ci", width: 70 },
            { label: "Fecha Nac.", property: "fecha", width: 80 },
            { label: "Teléfono", property: "telefono", width: 80 },
            { label: "Dirección", property: "direccion", width: 120 },
          ],
          datas: usuarios.map(u => ({
            nombre: u.nombre || "",
            apellidos: `${u.primerApellido || ""} ${u.segundoApellido || ""}`.trim(),
            ci: u.CedulaIdentidad || "",
            fecha: u.fechaNacimiento ? new Date(u.fechaNacimiento).toISOString().split("T")[0] : "",
            telefono: u.telefono || "",
            direccion: u.Direccion || ""
          })),
        };
  
        try {
          doc.table(table, {
            prepareHeader: () => doc.font("Helvetica-Bold").fontSize(12),
            prepareRow: (row, i) => doc.font("Helvetica").fontSize(10),
            columnSpacing: 5,
            padding: 5,
          });
        } catch (error) {
          console.error("Error al mostrar tabla en PDF:", error);
        }
      }
  
      doc.moveDown(3);
      doc.text("_________________________", { align: "right" });
      doc.text("Firma Responsable", { align: "right" });
  
      doc.end();
    });
  });
  

module.exports = router;
