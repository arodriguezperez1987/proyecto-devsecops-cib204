
'use strict';

// CIB-204 - Corrección de inyección SQL (CWE-89)
// Consulta parametrizada para evitar SQL Injection.

// Sin conexión real configurada para este laboratorio.
const conexion = null;

function buscarBitacora(nombre, callback) {
  const sql = 'SELECT * FROM bitacora WHERE usuario = ?';

  if (!conexion) {
    return callback(null, {
      sqlEjecutado: sql,
      parametros: [nombre],
      filas: []
    });
  }

  conexion.query(sql, [nombre], function (err, filas) {
    if (err) {
      return callback(null, {
        sqlEjecutado: sql,
        parametros: [nombre],
        filas: [],
        nota: err.code
      });
    }

    return callback(null, {
      sqlEjecutado: sql,
      parametros: [nombre],
      filas: filas
    });
  });
}

module.exports = { buscarBitacora };
