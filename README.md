# scripts

## instalation api kayros
```ps1
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/I-K-D-S/scripts/main/INSTALL_API.ps1" -OutFile "$env:TEMP\install_api.ps1"
Get-Content "$env:TEMP\install_api.ps1" | Out-File "$env:TEMP\install_api.ps1"  -Encoding UTF8NoBOM
PowerShell -ExecutionPolicy Bypass -File "$env:TEMP\install_api.ps1"
```
ou 
```ps1
curl -o "$env:TEMP\install_api.ps1" https://raw.githubusercontent.com/I-K-D-S/scripts/main/INSTALL_API.ps1
(Get-Content "$env:TEMP\install_api.ps1") | Set-Content "$env:TEMP\install_api.ps1" -Encoding utf8
PowerShell -ExecutionPolicy Bypass -File "$env:TEMP\install_api.ps1"
```