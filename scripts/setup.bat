@echo off
setlocal
cd /d "%~dp0.."
if "%RELAY_KEYSTORE_PASSWORD%"=="" (
  echo Defina RELAY_KEYSTORE_PASSWORD antes de executar.
  exit /b 1
)
if exist server.p12 (
  echo server.p12 ja existe. Nao sera sobrescrito.
  exit /b 1
)
if exist server.crt (
  echo server.crt ja existe. Nao sera sobrescrito.
  exit /b 1
)
keytool -genkeypair -alias servidor -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -dname "CN=Servidor Relay, OU=Seguranca, O=Trabalho Pratico 3" -validity 365 -keystore server.p12 -storetype PKCS12 -storepass "%RELAY_KEYSTORE_PASSWORD%" -keypass "%RELAY_KEYSTORE_PASSWORD%" -noprompt
if errorlevel 1 exit /b 1
keytool -exportcert -rfc -alias servidor -keystore server.p12 -storepass "%RELAY_KEYSTORE_PASSWORD%" -file server.crt
if errorlevel 1 exit /b 1
echo Certificado e keystore gerados.
