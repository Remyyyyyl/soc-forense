# Analizador de Logs Forense

**Aplicación web para análisis forense de logs Linux con IA local**

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📋 Descripción

Analizador de Logs Forense es una aplicación web diseñada para realizar análisis forense avanzado de logs del sistema operativo Linux. Utiliza modelos de IA local (integración con LM Studio) para proporcionar análisis inteligentes y detección de anomalías sin necesidad de enviar datos a servidores externos.

### Características principales

- 🔐 **Autenticación de usuarios** - Sistema seguro de registro y login
- 📊 **Dashboard intuitivo** - Vista general de análisis y estadísticas
- 📤 **Gestión de evidencia** - Subida y gestión de archivos de logs
- 🤖 **Análisis con IA local** - Integración con LM Studio para procesamiento inteligente
- 🔍 **Análisis detallado** - Detección de patrones, anomalías y amenazas
- 💾 **Base de datos** - Almacenamiento persistente de resultados
- 🎨 **Interfaz web moderna** - HTML templates con Jinja2

## 🚀 Inicio Rápido

### Requisitos previos

- Python 3.8 o superior
- [LM Studio](https://lmstudio.ai/) instalado y ejecutándose (para funcionalidad de IA)
- SQLite (incluido en Python)

### Instalación

1. **Clonar el repositorio**
```bash
git clone https://github.com/tu-usuario/analizador-de-logs.git
cd analizador-de-logs
```

2. **Crear entorno virtual**
```bash
python -m venv venv
```

3. **Activar entorno virtual**

**Windows:**
```bash
venv\Scripts\Activate.ps1
```

**Linux/Mac:**
```bash
source venv/bin/activate
```

4. **Instalar dependencias**
```bash
pip install -r requirements.txt
```

5. **Configurar variables de entorno**

Crear archivo `.env` en la raíz del proyecto:
```env
DEBUG=True
LM_STUDIO_URL=http://localhost:1234
DATABASE_URL=sqlite:///./logs_analysis.db
SECRET_KEY=tu-clave-secreta-aqui
```

6. **Inicializar base de datos**
```bash
python main.py
```

7. **Ejecutar la aplicación**
```bash
python main.py
```

La aplicación estará disponible en: `http://localhost:8000`

## 📁 Estructura del Proyecto

```
analizador-de-logs/
├── main.py                      # Punto de entrada de la aplicación
├── requirements.txt             # Dependencias del proyecto
├── README.md                    # Este archivo
├── .env                         # Variables de entorno (no incluido en git)
├── app/
│   ├── __init__.py
│   ├── database.py              # Configuración de base de datos
│   ├── dependencies.py          # Inyección de dependencias
│   ├── models.py                # Modelos SQLAlchemy
│   ├── schemas.py               # Esquemas Pydantic
│   ├── security.py              # Funciones de seguridad y autenticación
│   ├── crud/                    # Operaciones CRUD
│   │   ├── users.py
│   │   ├── evidence.py
│   │   └── analysis_results.py
│   ├── routers/                 # Rutas API
│   │   ├── auth.py              # Autenticación
│   │   ├── analysis.py          # Análisis de logs
│   │   ├── dashboard.py         # Dashboard
│   │   ├── evidence.py          # Gestión de evidencia
│   │   └── test.py              # Rutas de prueba
│   ├── services/                # Servicios de negocio
│   │   ├── lm_studio_client.py # Cliente para LM Studio
│   │   └── log_parser.py        # Parser de logs
│   └── templates/               # Plantillas HTML
│       ├── base.html
│       ├── auth/
│       │   ├── login.html
│       │   └── register.html
│       ├── dashboard/
│       │   └── overview.html
│       ├── analysis/
│       │   └── results.html
│       └── evidence/
│           ├── list.html
│           └── upload.html
├── evidence/                    # Almacenamiento de archivos de evidencia
│   ├── image/
│   └── raw/
└── logs/                        # Logs de la aplicación
```

## 🔧 Dependencias

- **FastAPI** - Framework web moderno
- **Uvicorn** - Servidor ASGI
- **SQLAlchemy** - ORM para base de datos
- **Pydantic** - Validación de datos
- **Jinja2** - Motor de plantillas
- **bcrypt/passlib** - Hashing de contraseñas
- **python-dotenv** - Gestión de variables de entorno
- **requests** - Cliente HTTP

Para más detalles, consulta [requirements.txt](requirements.txt)

## 💻 Uso

### Flujo típico de usuario

1. **Registrarse** - Crear cuenta de usuario en `/auth/register`
2. **Iniciar sesión** - Autenticarse en `/auth/login`
3. **Subir evidencia** - Cargar archivos de logs en `/evidence/upload`
4. **Analizar** - Procesar logs mediante IA local
5. **Ver resultados** - Consultar análisis en `/analysis/results`
6. **Dashboard** - Monitorear estadísticas en `/dashboard`

### Endpoints principales

- `POST /auth/register` - Registro de usuario
- `POST /auth/login` - Inicio de sesión
- `POST /evidence/upload` - Subir archivo de evidencia
- `GET /analysis/results/{evidence_id}` - Obtener resultados de análisis
- `GET /dashboard` - Ver dashboard
- `GET /test` - Pruebas de sistema

## 🤖 Integración con LM Studio

La aplicación se conecta con LM Studio para realizar análisis inteligente de logs. Asegúrate de:

1. Descargar e instalar [LM Studio](https://lmstudio.ai/)
2. Cargar un modelo de lenguaje en LM Studio
3. Iniciar el servidor local (generalmente en `http://localhost:1234`)
4. Configurar la URL en el archivo `.env`

## 🔐 Seguridad

- Contraseñas hasheadas con bcrypt
- Autenticación mediante JWT
- CORS configurado
- Variables sensibles en archivo `.env`
- Validación de entrada con Pydantic

## 📝 Contribuir

Las contribuciones son bienvenidas. Para cambios importantes:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## 👤 Autor

**Autor del Proyecto**

## 📞 Soporte

Para reportar bugs o sugerencias de mejora, abre un [Issue](https://github.com/tu-usuario/analizador-de-logs/issues) en el repositorio.

## 🗺️ Roadmap

- [ ] Exportación de reportes en PDF
- [ ] Análisis en tiempo real
- [ ] Integración con múltiples modelos de IA
- [ ] Panel de administración avanzado
- [ ] API REST completa
- [ ] Tests automatizados
- [ ] Documentación API (Swagger)

---

**Última actualización:** Septiembre 2024
