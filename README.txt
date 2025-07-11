SISTEMA DE CONTROL IoT - Lukoski Emiliano Dariel
================================================

Este sistema es una aplicación web para el control y monitoreo de dispositivos IoT a través de brokers MQTT.

DESCRIPCIÓN GENERAL
------------------
El sistema permite a los usuarios gestionar sus dispositivos IoT, configurar brokers MQTT y enviar comandos a los dispositivos de forma segura. Está diseñado para ser una solución completa que facilite la interacción con dispositivos IoT de manera intuitiva y segura, permitiendo a los usuarios tener control total sobre sus dispositivos a través de una interfaz web moderna.

COMPONENTES PRINCIPALES
----------------------

1. BACKEND (Flask)
-----------------
El backend está desarrollado en Python utilizando el framework Flask, que proporciona una base sólida para construir aplicaciones web. La implementación incluye:

- Sistema de autenticación robusto que utiliza sesiones para mantener el estado de los usuarios y proteger las rutas sensibles.
- Las contraseñas se almacenan de forma segura utilizando el algoritmo de hash scrypt, que es resistente a ataques de fuerza bruta.
- La comunicación con los brokers MQTT se realiza de forma asíncrona, permitiendo operaciones no bloqueantes y mejorando el rendimiento.
- Las credenciales de los brokers MQTT se encriptan usando Fernet, asegurando que la información sensible esté protegida.
- Se implementa una validación exhaustiva de las conexiones MQTT y DNS para garantizar la fiabilidad de las comunicaciones.
- Un sistema de logging detallado que registra todas las operaciones importantes para facilitar el diagnóstico de problemas.

2. FRONTEND
----------
La interfaz de usuario está construida con un enfoque en la experiencia del usuario y la accesibilidad:

- Utiliza Bootstrap 5 para crear una interfaz responsiva que se adapta a diferentes tamaños de pantalla.
- Implementa un sistema de temas claro/oscuro que persiste entre sesiones, mejorando la experiencia visual del usuario.
- Incorpora iconos de Bootstrap y Font Awesome para una interfaz más intuitiva y atractiva.
- Los mensajes flash proporcionan feedback inmediato al usuario sobre sus acciones.
- Los formularios incluyen validación tanto del lado del cliente como del servidor.
- Las tablas responsivas permiten una visualización clara de los datos en cualquier dispositivo.
- El diseño sigue las mejores prácticas de UX/UI para una experiencia de usuario óptima.

3. BASE DE DATOS (MySQL)
-----------------------
La base de datos está diseñada para almacenar y gestionar eficientemente la información del sistema:

- La tabla 'usuarios' almacena las credenciales de los usuarios y sus preferencias, como el tema de la interfaz.
- La tabla 'brokers' contiene la configuración de los brokers MQTT, incluyendo credenciales encriptadas.
- La tabla 'nodos' relaciona los dispositivos IoT con los usuarios y sus respectivos brokers.

4. DOCKER
--------
El sistema está containerizado para facilitar su despliegue y mantenimiento:

- El contenedor principal utiliza Python 3.11, asegurando compatibilidad con las últimas características del lenguaje.
- La configuración se maneja a través de variables de entorno, permitiendo flexibilidad en diferentes entornos.
- Se utiliza una red proxy para la comunicación entre servicios.
- Los datos persisten entre reinicios del contenedor.
- El sistema está configurado para reiniciarse automáticamente en caso de fallos.

FUNCIONALIDADES PRINCIPALES
--------------------------

1. Gestión de Usuarios
El sistema permite a los usuarios registrarse e iniciar sesión de forma segura. Durante el registro, se validan las credenciales y se almacenan de forma segura. El inicio de sesión utiliza sesiones para mantener el estado del usuario y proteger las rutas sensibles. Los usuarios pueden personalizar su experiencia seleccionando entre un tema claro u oscuro.

2. Gestión de Brokers MQTT
Los usuarios pueden agregar, editar y eliminar brokers MQTT. Cada broker se configura con su dominio, credenciales y puerto TLS. Las credenciales se almacenan de forma segura utilizando encriptación. El sistema valida la conectividad con los brokers antes de permitir su uso.

3. Gestión de Nodos IoT
Los usuarios pueden agregar nuevos dispositivos IoT y asociarlos a brokers específicos. Cada dispositivo se identifica con un nombre y un ID único. El sistema permite listar todos los dispositivos asociados a un usuario, facilitando su gestión.

4. Control de Dispositivos
Los usuarios pueden seleccionar un dispositivo activo y enviar comandos como destellos o configurar setpoints. La comunicación con los dispositivos se realiza a través de MQTT con TLS, asegurando que los datos se transmitan de forma segura.

SEGURIDAD
---------
El sistema implementa múltiples capas de seguridad para proteger los datos y las comunicaciones:

- Las contraseñas se hashean usando scrypt, un algoritmo resistente a ataques de fuerza bruta.
- Las credenciales de los brokers MQTT se encriptan usando Fernet.
- Las sesiones se gestionan de forma segura para proteger las rutas sensibles.
- Se implementa validación de datos para prevenir inyecciones SQL y otros ataques.
- La comunicación con los brokers MQTT utiliza TLS para asegurar la transmisión de datos.
- El sistema está protegido contra inyecciones SQL y otros ataques comunes.

REQUISITOS TÉCNICOS
------------------
Para ejecutar el sistema, se requiere:

- Python 3.11 o superior, que proporciona las características necesarias para el desarrollo.
- MySQL/MariaDB para el almacenamiento de datos.
- Docker y Docker Compose para la containerización y despliegue.
- Acceso a brokers MQTT con soporte TLS para la comunicación segura.

CONFIGURACIÓN
------------
El sistema se configura mediante variables de entorno, que incluyen:

- CRUD_USER: Usuario de la base de datos.
- CRUD_PASS: Contraseña de la base de datos.
- CRUD_DB: Nombre de la base de datos.
- MARIADB_SERVER: Servidor de la base de datos.
- FLASK_SECRET_KEY: Clave secreta para las sesiones de Flask.
- FERNET_KEY: Clave para la encriptación de credenciales.
- MQTT_*: Configuración del broker MQTT por defecto.

CONFIGURACIÓN DE RED Y PROXY INVERSO
-----------------------------------
El sistema está configurado para funcionar detrás de un proxy inverso SWAG (Secure Web Application Gateway):

- El contenedor SWAG actúa como proxy inverso y maneja las conexiones HTTPS.
- La configuración del proxy se realiza mediante el archivo `tareaflask2.subfolder.conf.sample` ubicado en `/swag/nginx/proxy-confs/`.
- El sistema redirige las peticiones de `/tareaflask2` a `/tareaflask2/` para mantener una estructura de URL consistente.
- Se configura el proxy para manejar correctamente los encabezados X-Forwarded-* para mantener la información del cliente original.

Arquitectura de Red:
- Todos los contenedores (crudflask2, SWAG, MariaDB, phpMyAdmin) están en la misma red Docker.
- La comunicación entre contenedores se realiza a través de esta red interna.
- El puerto 8001 del contenedor crudflask2 está expuesto internamente para la comunicación con SWAG.
- SWAG maneja la exposición segura del servicio al exterior a través de HTTPS.

Configuración del Proxy:
Como en el archivo de esta carpeta llamado tareaflask2.subfolder.conf.sample

Esta configuración asegura que:
- Las peticiones se redirijan correctamente al contenedor crudflask2.
- Se mantenga la información del cliente original.
- La aplicación funcione correctamente en un subdirectorio.
- La comunicación entre servicios sea segura y eficiente.
