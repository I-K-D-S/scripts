# Définition du dépôt et des fichiers à récupérer
$repoUrl = "https://raw.githubusercontent.com/TON_COMPTE/scripts-deploy/main"
$scripts = @("install_api.ps1", "setup_env.ps1", "configure_iis.ps1")
$logFile = "$env:TEMP\setup_log.txt"

# Fonction pour télécharger et exécuter un script
function Execute-Script($scriptName) {
    $url = "$repoUrl/$scriptName"
    $filePath = "$env:TEMP\$scriptName"
    
    try {
        Write-Host "📥 Téléchargement de $scriptName..."
        Invoke-WebRequest -Uri $url -OutFile $filePath -ErrorAction Stop
        
        if (Test-Path $filePath) {
            Write-Host "🚀 Exécution de $scriptName..."
            PowerShell -ExecutionPolicy Bypass -File $filePath | Out-File -Append $logFile
            Write-Host "✅ $scriptName exécuté avec succès."
        } else {
            Write-Host "❌ Échec du téléchargement de $scriptName."
        }
    } catch {
        Write-Host "❌ Erreur lors du téléchargement ou de l'exécution de $scriptName : $_"
        "[$(Get-Date)] Erreur: $_" | Out-File -Append $logFile
    }
}

# Début du processus
Write-Host "🔄 Début du processus de configuration..."
"[$(Get-Date)] Début du processus de configuration." | Out-File $logFile

foreach ($script in $scripts) {
    Execute-Script $script
}

Write-Host "📌 Logs enregistrés dans $logFile"
Write-Host "🎉 Installation terminée !"
"[$(Get-Date)] Fin du processus." | Out-File -Append $logFile