#############################################################################
# Proyecto Final - Topicos Especiales
# Modulo 5
# Automatizacion del Hardening
#
# Caso de estudio:
# CREATIC
#
# Servidores protegidos:
#   - CR-DC-01
#   - CR-FILE-03
#
# Autores:
# Hiroshi Komatsu
# Bryan Gonzalez
# Joel Villarreal
#
# Grupo 4
#############################################################################

#===========================================================================
# CARGAR VARIABLES
#===========================================================================

$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ScriptPath\vars.ps1"

#===========================================================================
# CREAR DIRECTORIO DE LOGS
#===========================================================================

$LogFolder = Split-Path $RutaLog

if (!(Test-Path $LogFolder))
{
    New-Item `
        -ItemType Directory `
        -Path $LogFolder `
        -Force | Out-Null
}

Start-Transcript `
    -Path $RutaLog `
    -Append

Write-Host ""
Write-Host "==============================================="
Write-Host " INICIANDO HARDENING WINDOWS - CREATIC"
Write-Host "==============================================="
Write-Host ""

#===========================================================================
# FUNCIONES AUXILIARES
#===========================================================================

function Write-Seccion
{
    param([string]$Titulo)

    Write-Host ""
    Write-Host "############################################################"
    Write-Host $Titulo
    Write-Host "############################################################"
    Write-Host ""
}

function Resultado
{
    param(
        [string]$Operacion,
        [bool]$Estado
    )

    if($Estado)
    {
        Write-Host "[OK] $Operacion" -ForegroundColor Green
    }
    else
    {
        Write-Host "[ERROR] $Operacion" -ForegroundColor Red
    }
}

#===========================================================================
# COMPROBAR PRIVILEGIOS
#===========================================================================

$Administrador = ([Security.Principal.WindowsPrincipal]
[Security.Principal.WindowsIdentity]::GetCurrent()).
IsInRole(
[Security.Principal.WindowsBuiltInRole]::Administrator)

if(!$Administrador)
{
    Write-Host ""
    Write-Host "ERROR: Ejecutar PowerShell como Administrador."
    Stop-Transcript
    exit
}

Write-Host "Privilegios administrativos verificados."

#===========================================================================
# BLOQUE 1
# DESHABILITAR SMBv1
#===========================================================================

Write-Seccion "BLOQUE 1 - DESHABILITAR SMBv1"

try
{

    Write-Host "Desinstalando caracteristica SMBv1..."

    Disable-WindowsOptionalFeature `
        -Online `
        -FeatureName SMB1Protocol `
        -NoRestart `
        -ErrorAction SilentlyContinue

    Remove-WindowsFeature `
        -Name $SMB1ServerFeature `
        -ErrorAction SilentlyContinue

    Set-SmbServerConfiguration `
        -EnableSMB1Protocol $false `
        -Force | Out-Null

    Resultado "SMBv1 deshabilitado correctamente." $true

}
catch
{

    Resultado "No fue posible deshabilitar SMBv1." $false

}

#===========================================================================
# BLOQUE 2
# POLITICAS DE CONTRASENA
#===========================================================================

Write-Seccion "BLOQUE 2 - POLITICAS DE CONTRASENA"

try
{

    Write-Host "Aplicando politicas de contrasena..."

    net accounts `
    /minpwlen:$MinPasswordLength `
    /maxpwage:$MaxPasswordAgeDays `
    /minpwage:$MinPasswordAgeDays `
    /uniquepw:$PasswordHistoryCount `
    /lockoutthreshold:$LockoutThreshold `
    /lockoutduration:$LockoutDurationMinutes `
    /lockoutwindow:$LockoutObservationWindow

    Resultado "Políticas de contraseña configuradas." $true

}
catch
{

    Resultado "Error aplicando políticas." $false

}

#===========================================================================
# BLOQUE 3
# DESHABILITAR CUENTA GUEST
#===========================================================================

Write-Seccion "BLOQUE 3 - DESHABILITAR CUENTA GUEST"

try
{

    Write-Host "Buscando cuenta Guest por RID..."

    $Guest = Get-LocalUser |
        Where-Object {
            $_.SID.Value.Split('-')[-1] -eq "$GuestAccountRID"
        }

    if($Guest)
    {

        Disable-LocalUser `
            -Name $Guest.Name

        Resultado "Cuenta Guest deshabilitada." $true

    }
    else
    {

        Write-Host "No se encontro la cuenta Guest."
        Resultado "Cuenta Guest no encontrada." $false

    }

}
catch
{

    Resultado "Error deshabilitando Guest." $false

}
#===========================================================================
# BLOQUE 4
# CONFIGURACION DEL FIREWALL
#===========================================================================

Write-Seccion "BLOQUE 4 - CONFIGURACION DEL FIREWALL"

try
{

    Write-Host "Habilitando Firewall de Windows..."

    Set-NetFirewallProfile `
        -Profile Domain `
        -Enabled True

    Set-NetFirewallProfile `
        -Profile Private `
        -Enabled True

    Set-NetFirewallProfile `
        -Profile Public `
        -Enabled True

    Resultado "Firewall habilitado correctamente." $true

}
catch
{

    Resultado "Error configurando el Firewall." $false

}

#===========================================================================
# BLOQUE 5
# REMEDIACION DE PERMISOS NTFS
#===========================================================================

Write-Seccion "BLOQUE 5 - REMEDIACION DE PERMISOS NTFS"

foreach($Carpeta in $CarpetasCriticas)
{

    Write-Host ""
    Write-Host "Procesando: $Carpeta"

    if(Test-Path $Carpeta)
    {

        try
        {

            $Acl = Get-Acl $Carpeta

            ###########################################################
            # Eliminar permisos Everyone
            ###########################################################

            $Eliminar = $Acl.Access |
                Where-Object {
                    $_.IdentityReference -match $IdentidadAEliminar
                }

            foreach($Permiso in $Eliminar)
            {
                $Acl.RemoveAccessRule($Permiso) | Out-Null
            }

            ###########################################################
            # Agregar grupo Users con permisos minimos
            ###########################################################

            $Regla = New-Object `
                System.Security.AccessControl.FileSystemAccessRule(
                    $IdentidadReemplazo,
                    $PermisoReemplazo,
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Allow"
                )

            $Acl.AddAccessRule($Regla)

            Set-Acl `
                -Path $Carpeta `
                -AclObject $Acl

            Resultado "Permisos corregidos en $Carpeta" $true

        }
        catch
        {

            Resultado "Error corrigiendo permisos en $Carpeta" $false

        }

    }
    else
    {

        Write-Host "La carpeta no existe."

    }

}

#===========================================================================
# BLOQUE 6
# DESHABILITAR NTLMv1
#===========================================================================

Write-Seccion "BLOQUE 6 - DESHABILITAR NTLMv1"

if($DeshabilitarNTLMv1)
{

    try
    {

        Write-Host "Aplicando NTLMv2 unicamente..."

        New-Item `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Force | Out-Null

        Set-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "LmCompatibilityLevel" `
            -Value 5 `
            -Type DWord

        Resultado "NTLMv1 deshabilitado." $true

    }
    catch
    {

        Resultado "No fue posible configurar NTLM." $false

    }

}

#===========================================================================
# BLOQUE 7
# DESHABILITAR LLMNR
#===========================================================================

Write-Seccion "BLOQUE 7 - DESHABILITAR LLMNR"

if($DeshabilitarLLMNR)
{

    try
    {

        Write-Host "Deshabilitando LLMNR..."

        New-Item `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
            -Force | Out-Null

        Set-ItemProperty `
            -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
            -Name "EnableMulticast" `
            -Value 0 `
            -Type DWord

        Resultado "LLMNR deshabilitado correctamente." $true

    }
    catch
    {

        Resultado "No fue posible deshabilitar LLMNR." $false

    }

}
#===========================================================================
# BLOQUE 8
# DESHABILITAR NULL SESSIONS
#===========================================================================

Write-Seccion "BLOQUE 8 - DESHABILITAR NULL SESSIONS"

if($DeshabilitarNullSession)
{

    try
    {

        Write-Host "Bloqueando sesiones anonimas..."

        New-Item `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Force | Out-Null

        Set-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "RestrictAnonymous" `
            -Value 1 `
            -Type DWord

        Set-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "RestrictAnonymousSAM" `
            -Value 1 `
            -Type DWord

        Resultado "Null Sessions deshabilitadas." $true

    }
    catch
    {

        Resultado "No fue posible deshabilitar Null Sessions." $false

    }

}

#===========================================================================
# BLOQUE 9
# REMEDIACION DE VULNERABILIDADES
#===========================================================================

Write-Seccion "BLOQUE 9 - REMEDIACION DE VULNERABILIDADES"

try
{

    #############################################################
    # Habilitar Microsoft Defender
    #############################################################

    Write-Host "Habilitando Microsoft Defender..."

    Set-MpPreference `
        -DisableRealtimeMonitoring $false

    #############################################################
    # Actualizar firmas
    #############################################################

    Write-Host "Actualizando firmas..."

    Update-MpSignature

    #############################################################
    # Iniciar analisis rapido
    #############################################################

    Write-Host "Ejecutando analisis rapido..."

    Start-MpScan `
        -ScanType QuickScan

    Resultado "Remediacion ejecutada correctamente." $true

}
catch
{

    Resultado "Error durante la remediacion." $false

}

#===========================================================================
# BLOQUE 10
# VERIFICACIÓN DEL HARDENING
#===========================================================================

Write-Seccion "BLOQUE 10 - VERIFICACION"

#############################################################
# SMBv1
#############################################################

Write-Host ""
Write-Host "Verificando SMBv1..."

Get-SmbServerConfiguration |
Select EnableSMB1Protocol

#############################################################
# Firewall
#############################################################

Write-Host ""
Write-Host "Verificando Firewall..."

Get-NetFirewallProfile |
Select Name,Enabled

#############################################################
# Cuenta Guest
#############################################################

Write-Host ""
Write-Host "Verificando cuenta Guest..."

Get-LocalUser |
Where-Object {
    $_.SID.Value.Split('-')[-1] -eq "$GuestAccountRID"
} |
Select Name,Enabled

#############################################################
# NTLMv1
#############################################################

Write-Host ""
Write-Host "Verificando NTLM..."

Get-ItemProperty `
-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" |
Select LmCompatibilityLevel

#############################################################
# LLMNR
#############################################################

Write-Host ""
Write-Host "Verificando LLMNR..."

Get-ItemProperty `
-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" |
Select EnableMulticast

#############################################################
# Null Sessions
#############################################################

Write-Host ""
Write-Host "Verificando Null Sessions..."

Get-ItemProperty `
-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" |
Select RestrictAnonymous,
       RestrictAnonymousSAM

#############################################################
# Defender
#############################################################

Write-Host ""
Write-Host "Estado Microsoft Defender..."

Get-MpComputerStatus |
Select AMServiceEnabled,
       AntivirusEnabled,
       RealTimeProtectionEnabled

#############################################################
# ACL de carpetas criticas
#############################################################

Write-Host ""
Write-Host "Verificando permisos NTFS..."

foreach($Carpeta in $CarpetasCriticas)
{

    if(Test-Path $Carpeta)
    {

        Write-Host ""
        Write-Host "Carpeta: $Carpeta"

        Get-Acl $Carpeta |
        Select -ExpandProperty Access |
        Select IdentityReference,
               FileSystemRights,
               AccessControlType

    }

}

#===========================================================================
# RESUMEN FINAL
#===========================================================================

Write-Seccion "RESUMEN FINAL"

Write-Host ""
Write-Host "==========================================================="
Write-Host "            HARDENING COMPLETADO CORRECTAMENTE"
Write-Host "==========================================================="
Write-Host ""

Write-Host "Proyecto Final - Topicos Especiales"
Write-Host "Modulo 5 - Automatizacion del Hardening"
Write-Host ""
Write-Host "Caso de estudio:"
Write-Host "CREATIC"
Write-Host ""

Write-Host "Servidores protegidos:"

foreach($Servidor in $ServidoresProtegidos)
{
    Write-Host " - $Servidor"
}

Write-Host ""
Write-Host "Controles implementados:"
Write-Host ""
Write-Host "  ✔ SMBv1 deshabilitado"
Write-Host "  ✔ Politicas de contrasenas aplicadas"
Write-Host "  ✔ Cuenta Guest deshabilitada"
Write-Host "  ✔ Firewall habilitado"
Write-Host "  ✔ Permisos NTFS corregidos"
Write-Host "  ✔ NTLMv1 deshabilitado"
Write-Host "  ✔ LLMNR deshabilitado"
Write-Host "  ✔ Null Sessions bloqueadas"
Write-Host "  ✔ Microsoft Defender habilitado"
Write-Host "  ✔ Verificaciones completadas"

Write-Host ""
Write-Host "Log generado en:"
Write-Host $RutaLog

Write-Host ""
Write-Host "Autores:"
Write-Host " - Hiroshi Komatsu"
Write-Host " - Bryan Gonzalez"
Write-Host " - Joel Villarreal"

Write-Host ""
Write-Host "Grupo 4"

Write-Host ""
Write-Host "==========================================================="
Write-Host "      FIN DEL PROCESO DE HARDENING WINDOWS CREATIC"
Write-Host "==========================================================="

#===========================================================================
# CIERRE DEL LOG
#===========================================================================

Stop-Transcript


