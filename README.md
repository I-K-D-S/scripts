# scripts

## instalation api kayros
````ps1
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/TON_COMPTE/scripts-deploy/main/install_api.ps1" -OutFile "$env:TEMP\install_api.ps1"
PowerShell -ExecutionPolicy Bypass -File "$env:TEMP\install_api.ps1"
```
ou 
```ps1
curl -o "$env:TEMP\install_api.ps1" https://raw.githubusercontent.com/TON_COMPTE/scripts-deploy/main/install_api.ps1
PowerShell -ExecutionPolicy Bypass -File "$env:TEMP\install_api.ps1"
``