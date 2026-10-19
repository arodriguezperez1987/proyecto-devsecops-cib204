// ============================================================================
//  servidor.js  -  API REST del servicio de cifrado
//  CIB-204 Seguridad del Software - Universidad Cenfotec
//  >>> VERSION INSEGURA (rama inseguro) <<<
//
//  Endpoints:
//    GET  /salud       -> estado del servicio
//    GET  /llave       -> entrega la llave publica
//    POST /cifrar      -> cifra un texto
//    POST /descifrar   -> descifra un texto
//    GET  /buscar      -> consulta la bitacora (demostracion de SQLi)
//    POST /calcular    -> "utilidad" de calculo (demostracion de eval)
//    GET  /diagnostico -> ejecuta un ping (demostracion de command injection)
// ============================================================================

const express = require('express');
const cors = require('cors');
const { execFile } = require('child_process');
const { isIP } = require('node:net');
const cifrado = require('./cifrado');
const db = require('./db');
const config = require('./config');
const { requireAuth: requiereAuth } = require('./auth');

const app = express();
app.use(express.json());

// [VULN-5] CORS totalmente abierto: cualquier origen puede consumir la API.
//   Lo reporta OWASP ZAP (DAST) y Semgrep. La solucion es restringir a los
//   origenes de confianza.  CWE-942 (Overly Permissive CORS)
app.use(cors());

// [VULN-6] Faltan cabeceras de seguridad (no se usa Helmet):
//   sin Content-Security-Policy, X-Content-Type-Options, etc.
//   Lo reporta OWASP ZAP.  CWE-693 (Protection Mechanism Failure)
//   (La solucion es: app.use(require('helmet')()).)

// El servicio genera su par de llaves al arrancar.
const llaves = cifrado.generarLlaves();

app.get('/salud', (req, res) => {
  res.json({ estado: 'ok', version: 'inseguro-1.0' });
});

app.get('/llave', (req, res) => {
  res.json({ llavePublica: llaves.publicKey });
});

app.post('/cifrar', requiereAuth, (req, res) => {
  try {
    // [VULN-7] Sin validacion de entrada: no se controla tipo ni tamano.
    //   Un cuerpo enorme o de tipo inesperado puede tumbar el servicio.
    //   CWE-20 (Improper Input Validation)
    const texto = req.body?.texto;

// Validar tipo, contenido y longitud del texto
if (
  typeof texto !== 'string' ||
  texto.trim().length === 0 ||
  texto.length > 180
) {
  return res.status(400).json({
    error: 'El texto debe contener entre 1 y 180 caracteres'
  });
}

const resultado = cifrado.cifrar(texto, llaves.publicKey);
res.json({ cifrado: resultado });
  } catch (e) {
  console.error('Error durante el cifrado:', e);

  return res.status(500).json({
    error: 'No fue posible procesar la solicitud de cifrado'
  });
}
});

app.post('/descifrar', requiereAuth, (req, res) => {
  try {
    const cifradoTxt = req.body.cifrado;
    const resultado = cifrado.descifrar(cifradoTxt, llaves.privateKey);
    res.json({ descifrado: resultado });
  } catch (e) {
    res.status(500).json({ error: e.message, stack: e.stack });
  }
});

// Demostracion de INYECCION SQL (CWE-89).
app.get('/buscar', (req, res) => {
  const nombre = req.query.nombre || '';
  db.buscarBitacora(nombre, (err, data) => {
    res.json(data);
  });
});

// [VULN-9] Uso de eval() sobre entrada del usuario: inyeccion de codigo.
//   Lo detectan Semgrep y CodeQL (js/code-injection).
//   CWE-95 (Eval Injection)
app.post('/calcular', (req, res) => {
  const expresion = req.body?.expresion;

  if (typeof expresion !== 'string') {
    return res.status(400).json({
      error: 'Expresion invalida'
    });
  }

  const patron = /^\s*(-?\d+(?:\.\d+)?)\s*([+\-*/])\s*(-?\d+(?:\.\d+)?)\s*$/;
  const coincidencia = expresion.match(patron);

  if (!coincidencia) {
    return res.status(400).json({
      error: 'Expresion invalida'
    });
  }

  const numero1 = Number(coincidencia[1]);
  const operador = coincidencia[2];
  const numero2 = Number(coincidencia[3]);

  let resultado;

  switch (operador) {
    case '+':
      resultado = numero1 + numero2;
      break;
    case '-':
      resultado = numero1 - numero2;
      break;
    case '*':
      resultado = numero1 * numero2;
      break;
    case '/':
      if (numero2 === 0) {
        return res.status(400).json({
          error: 'Division entre cero no permitida'
        });
      }
      resultado = numero1 / numero2;
      break;
  }

  if (!Number.isFinite(resultado)) {
    return res.status(400).json({
      error: 'Resultado fuera de rango'
    });
  }

  return res.json({ resultado });
});
// [VULN-10] Inyeccion de comandos del sistema operativo.
//   El parametro 'host' entra sin sanitizar a exec(). Un atacante puede enviar
//   "8.8.8.8; cat /etc/passwd". Lo detectan CodeQL y Semgrep.
//   CWE-78 (OS Command Injection)
app.get('/diagnostico', (req, res) => {
  const host = req.query.host || '127.0.0.1';

  if (typeof host !== 'string' || isIP(host) === 0) {
    return res.status(400).json({
      error: 'Direccion IP invalida'
    });
  }

  execFile(
    'ping',
    ['-c', '1', '--', host],
    { timeout: 5000 },
    (err, stdout, stderr) => {
      if (err) {
        return res.status(500).json({
          error: 'No fue posible completar el diagnostico'
        });
      }

      return res.json({
        salida: stdout,
        error: stderr
      });
    }
  );
});

if (require.main === module) {
  app.listen(config.PUERTO, () => {
    console.log('Servicio de cifrado escuchando en el puerto ' + config.PUERTO);
    console.log('AUTH_ENABLED =', config.AUTH_ENABLED);
  });
}

module.exports = app;
