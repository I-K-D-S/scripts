# scripts

## instalation api kayros
```ps1
$scriptUrl="https://raw.githubusercontent.com/I-K-D-S/scripts/main/INSTALL_API.ps1"; $dest="$env:TEMP\install_api.ps1"; Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing -OutFile $dest; [System.IO.File]::WriteAllText($dest,[System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($dest)),[System.Text.Encoding]::UTF8); PowerShell -ExecutionPolicy Bypass -File $dest
```
