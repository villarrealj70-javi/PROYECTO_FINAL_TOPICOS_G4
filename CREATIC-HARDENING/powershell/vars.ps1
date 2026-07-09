#############################################################################
# vars.ps1
# Variables de configuracion para el hardening de servidores Windows CREATIC
# Equivalente funcional al vars.yml usado en el playbook de Ansible.
# NINGUN valor debe quedar "hardcodeado" dentro de Hardening-CREATIC.ps1;
# todo parametro editable vive en este archivo.
#############################################################################

# --- Politica de contrasenas (CIS Benchmark Windows Server, seccion 1.1) ---
$MinPasswordLength        = 14      # Longitud minima de contrasena
$PasswordHistoryCount     = 24      # Contrasenas anteriores recordadas
$MaxPasswordAgeDays       = 90      # Vigencia maxima antes de forzar cambio
$MinPasswordAgeDays       = 1       # Evita cambios en cadena para burlar el historial
$LockoutThreshold         = 5       # Intentos fallidos antes de bloquear cuenta
$LockoutDurationMinutes   = 30      # Minutos que la cuenta permanece bloqueada
$LockoutObservationWindow = 30      # Minutos del contador de intentos fallidos

# --- Cuenta de invitado ---
# Se identifica por RID 501 (no por nombre), ya que el nombre "Guest"/"Invitado"
# puede variar segun el idioma o haber sido renombrado manualmente.
$GuestAccountRID = 501

# --- SMBv1 ---
$SMB1ServerFeature = "FS-SMB1"      # Feature de Windows que instala el servidor SMBv1

# --- Remediacion de permisos NTFS (carpetas administrativas de CR-FILE-03) ---
# Rutas sensibles donde debe eliminarse el acceso amplio del grupo Everyone/Todos.
# Ajustar segun el inventario real de shares del servidor.
$CarpetasCriticas = @(
    "D:\Shares\Administracion",
    "D:\Shares\Finanzas"
)
$IdentidadAEliminar = "Everyone"    # Grupo a remover de las ACL (equivale a "Todos")
$IdentidadReemplazo = "BUILTIN\Users" # Grupo con el que se reemplaza el acceso amplio
$PermisoReemplazo   = "ReadAndExecute"

# --- Remediacion de protocolos legados / superficie de ataque ---
$DeshabilitarNTLMv1     = $true     # Fuerza NTLMv2 unicamente (LmCompatibilityLevel = 5)
$DeshabilitarLLMNR      = $true     # Mitiga envenenamiento LLMNR/NBT-NS (responder attacks)
$DeshabilitarNullSession = $true    # Bloquea enumeracion anonima de shares/usuarios

# --- Logging / evidencia de ejecucion ---
$RutaLog = "C:\CREATIC\Hardening\Logs\hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# --- Identificacion del proyecto (para el resumen final) ---
$ServidoresProtegidos = @("CR-DC-01", "CR-FILE-03")
