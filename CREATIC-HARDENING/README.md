# UNIVERSIDAD TECNOLÓGICA DE PANAMÁ
### Facultad de Ingeniería de Sistemas Computacionales
### Licenciatura en Ingeniería de Sistemas y Computación
### Tópicos Especiales

## Proyecto Final
### Diseño e Implementación de Plan Integral de Ciberseguridad
**Caso de estudio: CREATIC**

**Integrantes (Grupo 4):**
- Hiroshi Komatsu
- Bryan González
- Joel Villarreal

**Facilitador:** Prof. Xavier Trujillo

**Fecha:** 9 de julio de 2026

---

## Módulo 5 — Automatización del Hardening

Para este módulo se desarrollaron scripts de automatización para aplicar el hardening 
de seguridad a los servidores del Instituto Tecnológico CREATIC, cubriendo tanto los 
servidores Linux (mediante Ansible) como los servidores Windows Server (mediante 
PowerShell).

### 🔧 Hardening Linux (Ansible) — CR-APPSRV-02 y CR-DB-01

- **`inventory.ini`**: Inventario de Ansible con los hosts `CR-APPSRV-02` y `CR-DB-01` 
  definidos como servidores del grupo `linux_servers`.
- **`vars.yml`**: Variables centralizadas del playbook (puerto SSH personalizado, 
  política de acceso root, puertos permitidos en el firewall, servicios a deshabilitar, 
  etc.), evitando valores "hardcodeados" dentro del playbook.
- **`playbook.yml`**: Playbook principal que ejecuta el hardening en 7 bloques:
  1. Actualización del sistema operativo (apt update/upgrade).
  2. Hardening del servicio SSH (cambio de puerto, deshabilitación de login root).
  3. Configuración del firewall UFW (políticas de entrada/salida, apertura de puertos 
     autorizados).
  4. Deshabilitación de servicios innecesarios (telnet, ftp).
  5. Remediación de vulnerabilidades (eliminación de paquetes obsoletos, limpieza de caché).
  6. Verificación del hardening (estado de SSH, firewall, puerto configurado, acceso root).
  7. Resumen final del proceso.

### 🔧 Hardening Windows (PowerShell) — CR-DC-01 y CR-FILE-03

- **`vars.ps1`**: Variables de configuración equivalentes al `vars.yml` usado en Ansible. 
  Ningún valor queda "hardcodeado" dentro de `hardening.ps1`; todo parámetro editable 
  vive en este archivo (política de contraseñas, RID de la cuenta Guest, carpetas 
  críticas a remediar, feature de SMBv1, etc.).
- **`hardening.ps1`**: Script principal que automatiza la aplicación de configuraciones 
  de seguridad en 10 bloques:
  1. Deshabilitación del protocolo SMBv1.
  2. Aplicación de políticas de contraseñas (longitud mínima, vigencia, historial, bloqueo de cuenta).
  3. Deshabilitación de la cuenta Guest (identificada por RID, no por nombre).
  4. Habilitación del Firewall de Windows en los tres perfiles (Domain, Private, Public).
  5. Remediación de permisos NTFS en carpetas críticas (eliminación de acceso del grupo "Everyone").
  6. Deshabilitación de NTLMv1 (forzando NTLMv2).
  7. Deshabilitación de LLMNR.
  8. Bloqueo de Null Sessions (sesiones anónimas).
  9. Remediación adicional: habilitación de Microsoft Defender, actualización de firmas 
     y análisis rápido.
  10. Verificación final de todos los controles aplicados, con generación de log mediante 
      `Start-Transcript`.

### ⚠️ Nota sobre el entorno de laboratorio

Para el desarrollo del laboratorio se utilizó una única máquina virtual con Debian, la 
cual representó de forma lógica los servidores `CR-APPSRV-02` y `CR-DB-01` definidos 
en el caso de estudio de CREATIC. Debido a esta configuración, el archivo `inventory.ini` 
fue implementado utilizando el parámetro `ansible_connection=local`, permitiendo 
ejecutar el playbook directamente sobre el sistema local sin requerir una conexión SSH 
entre múltiples máquinas virtuales.

Esta decisión se tomó con el propósito de simplificar el entorno de pruebas y validar el 
funcionamiento del proceso de automatización del hardening. **En un entorno de 
producción, el mismo playbook puede utilizarse sin modificaciones, reemplazando 
únicamente el contenido del archivo `inventory.ini` por las direcciones IP reales de los 
servidores administrados mediante SSH.**
