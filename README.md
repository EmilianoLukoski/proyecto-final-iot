# VoltLogger - Sistema de Monitoreo IoT
## Sistema de Control y Monitoreo de Dispositivos IoT - Lukoski Emiliano Dariel

Este sistema es una aplicación web completa para el control y monitoreo de dispositivos IoT a través de brokers MQTT, con capacidades avanzadas de visualización de datos y detección de eventos anómalos.

## 📋 Descripción General

VoltLogger es una solución integral que permite a los usuarios gestionar sus dispositivos IoT, configurar brokers MQTT, monitorear datos en tiempo real y detectar eventos anómalos de forma segura. Está diseñado para ser una plataforma completa que facilite la interacción con dispositivos IoT de manera intuitiva y segura, proporcionando dashboards avanzados para el análisis de datos.

## 🏗️ Componentes Principales

### 1. BACKEND (Flask)
El backend está desarrollado en Python utilizando el framework Flask, proporcionando una base sólida para construir aplicaciones web:

- Sistema de autenticación robusto: Utiliza sesiones para mantener el estado de los usuarios y proteger las rutas sensibles
- Seguridad avanzada: Las contraseñas se almacenan usando el algoritmo de hash scrypt, resistente a ataques de fuerza bruta
- Comunicación MQTT asíncrona: Realizada de forma asíncrona permitiendo operaciones no bloqueantes y mejorando el rendimiento
- Encriptación de credenciales: Las credenciales de los brokers MQTT se encriptan, asegurando protección de información sensible
- Validación exhaustiva: Se implementa validación de conexiones MQTT y DNS para garantizar fiabilidad
- Sistema de logging detallado: Registra todas las operaciones importantes para facilitar el diagnóstico

### 2. FRONTEND
La interfaz de usuario está construida con un enfoque en la experiencia del usuario y la accesibilidad:

- Bootstrap 5: Interfaz responsiva que se adapta a diferentes tamaños de pantalla
- Sistema de temas dinámico: Tema claro/oscuro que persiste entre sesiones y se actualiza dinámicamente
- Iconos modernos: Bootstrap y Font Awesome para una interfaz intuitiva y atractiva
- Feedback inmediato: Mensajes flash proporcionan retroalimentación al usuario
- Validación dual: Formularios con validación tanto del lado del cliente como del servidor
- Tablas responsivas: Visualización clara de datos en cualquier dispositivo
- Diseño UX/UI optimizado: Sigue las mejores prácticas para una experiencia óptima

### 3. BASE DE DATOS (MySQL + InfluxDB)
Sistema de almacenamiento híbrido diseñado para máxima eficiencia:

#### MySQL (Datos de configuración):
- Tabla 'usuarios': Credenciales de usuarios y preferencias (tema de interfaz)
- Tabla 'brokers': Configuración de brokers MQTT con credenciales encriptadas
- Tabla 'nodos': Relación entre dispositivos IoT, usuarios y brokers
- Tabla 'eventos': Almacenamiento de eventos anómalos detectados

#### InfluxDB (Datos de series temporales):
- Almacenamiento optimizado: Para datos de tensión y frecuencia en tiempo real
- Retención configurable: Políticas de retención de datos personalizables
- Consultas eficientes: Optimizado para análisis temporal de datos

### 4. DOCKER
El sistema está completamente containerizado para facilitar su despliegue:

- Contenedor principal: Python 3.11 con todas las dependencias
- Configuración flexible: Variables de entorno para diferentes entornos
- Red proxy: Comunicación segura entre servicios
- Persistencia de datos: Datos preservados entre reinicios
- Auto-recuperación: Reinicio automático en caso de fallos

## 🚀 Funcionalidades Principales

### 1. Gestión de Usuarios
- Registro seguro: Validación de credenciales y almacenamiento seguro
- Inicio de sesión: Sistema de sesiones para mantener estado del usuario
- Personalización: Selección de tema claro/oscuro con persistencia
- Protección de rutas: Middleware de autenticación para rutas sensibles

### 2. Gestión de Brokers MQTT
- Configuración completa: Agregar, editar y eliminar brokers MQTT
- Validación de conectividad: Verificación automática de conexiones
- Encriptación: Credenciales almacenadas de forma segura
- Configuración TLS: Soporte completo para conexiones seguras

### 3. Gestión de Nodos IoT
- Asociación de dispositivos: Vincular dispositivos con brokers específicos
- Identificación única: Sistema de IDs únicos para cada dispositivo
- Listado organizado: Visualización clara de dispositivos por usuario
- Selección dinámica: Cambio de dispositivo activo en tiempo real

### 4. Dashboards Avanzados

#### Dashboard de Tensión
- Visualización en tiempo real: Gráficos interactivos con Chart.js
- Rangos de tiempo configurables: Últimos 30 min, 1 hora, 6 horas, 1 día, 3 días, 1 semana
- Estadísticas automáticas: Valores actual, máximo, mínimo y promedio
- Detección de estados: Normal, Caída, Interrupción, Sobretensión
- Exportación de datos: CSV y PDF con formato optimizado
- Ejes dinámicos: Formato automático según rango de tiempo

#### Dashboard de Frecuencia
- Monitoreo continuo: Datos de frecuencia en tiempo real
- Análisis temporal: Visualización de tendencias y patrones
- Estados automáticos: Baja, Normal, Alta según rangos estándar
- Exportación completa: Datos en formatos CSV y PDF
- Interfaz consistente: Misma experiencia que el dashboard de tensión

#### Dashboard de Eventos
- Detección automática: Eventos anómalos capturados en tiempo real
- Paginación inteligente: 3 eventos por página para mejor navegación
- Panel de estadísticas: Total de eventos, duración promedio, eventos en curso
- Gráfico de eventos diarios: Visualización de eventos por día/semana
- Cálculo de duración: Tiempo transcurrido entre inicio y fin de eventos
- Exportación detallada: Información completa en CSV y PDF
- Tema dinámico: Colores que se adaptan automáticamente al tema

### 5. Control de Dispositivos
- Selección dinámica: Cambio de dispositivo activo en tiempo real
- Comandos seguros: Envío de comandos a través de MQTT con TLS
- Monitoreo de estado: Verificación de conectividad en tiempo real
- Workers automáticos: Inicio automático de monitoreo por dispositivo

### 6. Funcionalidades de Exportación
- Exportación CSV: Datos formateados para análisis externo
- Exportación PDF: Reportes profesionales con estadísticas
- Sin caracteres especiales: Codificación optimizada para compatibilidad universal
- Formato consistente: Estructura uniforme en todos los dashboards

## 🔒 Seguridad

El sistema implementa múltiples capas de seguridad:

- Hashing avanzado: Contraseñas hasheadas con scrypt
- Encriptación de credenciales: Para datos sensibles
- Gestión segura de sesiones: Protección de rutas sensibles
- Validación de datos: Prevención de inyecciones SQL y otros ataques
- Comunicación TLS: MQTT sobre TLS para transmisión segura
- Protección CSRF: Tokens de seguridad en formularios
- Headers de seguridad: Configuración CORS y otras protecciones

## 📊 Características Técnicas Avanzadas

### Monitoreo en Tiempo Real
- Workers MQTT: Hilos independientes por dispositivo
- Suscripción automática: Tópicos voltlogger/{device_id}/tension, frecuencia, eventos
- Procesamiento asíncrono: Sin bloqueo de la interfaz principal
- Reconexión automática: Recuperación automática de conexiones perdidas

### Visualización de Datos
- Chart.js avanzado: Gráficos interactivos y responsivos
- Actualización dinámica: Datos que se actualizan automáticamente
- Temas adaptativos: Colores que cambian según el tema seleccionado
- Optimización de rendimiento: Límites de datos y paginación

### Gestión de Eventos
- Detección automática: Captura de eventos anómalos desde MQTT
- Almacenamiento estructurado: Fases de eventos (inicio, peor, fin)
- Análisis temporal: Cálculo automático de duraciones
- Categorización: Tipos de eventos y estados

## 🛠️ Requisitos Técnicos

Para ejecutar el sistema se requiere:

- Python 3.11+: Características avanzadas del lenguaje
- MySQL/MariaDB: Almacenamiento de datos de configuración
- InfluxDB: Base de datos de series temporales
- Docker y Docker Compose: Containerización y despliegue
- Brokers MQTT: Con soporte TLS para comunicación segura

## 🌐 Configuración de Red y Proxy Inverso

El sistema está optimizado para funcionar detrás de un proxy inverso:

- Contenedor SWAG: Proxy inverso con manejo de HTTPS
- Configuración automática: Headers X-Forwarded-* manejados correctamente
- Red interna: Comunicación segura entre contenedores
- Puerto configurable: Puerto personalizable para comunicación con el proxy

## 📈 Monitoreo y Mantenimiento

### Logs del Sistema:
- Logs de aplicación: Flask con formato estructurado
- Logs de MQTT: Conexiones y mensajes procesados
- Logs de base de datos: Operaciones de lectura/escritura
- Logs de Docker: Estado de contenedores

### Métricas de Rendimiento:
- Tiempo de respuesta: APIs y dashboards
- Uso de memoria: Contenedores y aplicaciones
- Conexiones MQTT: Estado y estabilidad
- Almacenamiento: Uso de MySQL e InfluxDB

## 🔧 Desarrollo y Contribución

### Estructura del Código:
- Modular: Separación clara de responsabilidades
- Documentado: Comentarios explicativos en funciones clave
- Testeable: Funciones con responsabilidades únicas
- Escalable: Arquitectura preparada para crecimiento

### Mejores Prácticas Implementadas:
- Principio DRY: Código reutilizable y mantenible
- Separación de concerns: Lógica de negocio separada de presentación
- Manejo de errores: Try-catch comprehensivo
- Logging estructurado: Trazabilidad completa de operaciones

## 📞 Soporte y Contacto

Para soporte técnico o consultas:
- Email: emidariel2012@gmail.com
- Proyecto: Sistema de Control IoT - VoltLogger
- Desarrollador: Lukoski Emiliano Dariel

**VoltLogger** - Monitoreo inteligente para dispositivos IoT
