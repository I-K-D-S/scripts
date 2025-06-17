param (
    [switch]$NoRestart,
    [switch]$SkipRestart
)

# Fonctions d'affichage harmonisées
function Write-Separator { Write-Host ("-"*60) -ForegroundColor DarkGray }
function Write-Info($msg)    { Write-Host "ℹ️  $msg" -ForegroundColor Cyan }
function Write-Success($msg) { Write-Host "✅ $msg" -ForegroundColor Green }
function Write-Warn($msg)    { Write-Host "⚠️  $msg" -ForegroundColor Yellow }
function Write-ErrorMsg($msg){ Write-Host "❌ $msg" -ForegroundColor Red }

# Affichage ASCII Art KAYROS API
function Show-AsciiArt {
    1..6 | ForEach-Object { Write-Host "" }
    Write-Host @"
    ___  __    ________      ___    ___ ________  ________  ________      
    |\  \|\  \ |\   __  \    |\  \  /  /|\   __  \|\   __  \|\   ____\     
    \ \  \/  /|\ \  \|\  \   \ \  \/  / | \  \|\  \ \  \|\  \ \  \___|_    
     \ \   ___  \ \   __  \   \ \    / / \ \   _  _\ \  \\\  \ \_____  \   
      \ \  \\ \  \ \  \ \  \   \/  /  /   \ \  \\  \\ \  \\\  \|____|\  \  
       \ \__\\ \__\ \__\ \__\__/  / /      \ \__\\ _\\ \_______\____\_\  \ 
        \|__| \|__|\|__|\|__|\___/ /        \|__|\|__|\|_______|\_________\
                            \|___|/                            \|_________|
     ________  ________  ___                                               
    |\   __  \|\   __  \|\  \                                              
    \ \  \|\  \ \  \|\  \ \  \                                             
     \ \   __  \ \   ____\ \  \                                            
      \ \  \ \  \ \  \___|\ \  \                                           
       \ \__\ \__\ \__\    \ \__\                                          
        \|__|\|__|\|__|     \|__|                                            
"@ -ForegroundColor Magenta
    Write-Separator
}

# Définir le chemin du fichier indicateur
$tempIndicatorPath = "$env:TEMP\kayros_install_indicator.txt"

# Vérifier si PowerShell est lancé en mode Administrateur
$elevated = ([System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $elevated -and -not $NoRestart -and -not $SkipRestart) {
    Write-Warn "Le script nécessite des privilèges administrateur pour certaines parties. Redémarrage en mode Admin..."
    Start-Process PowerShell -ArgumentList "-File `"$PSCommandPath`" -NoRestart -SkipRestart" -Verb RunAs
    exit
}

Show-AsciiArt

# Créer le fichier indicateur pour éviter les redémarrages en boucle
if (!(Test-Path $tempIndicatorPath)) {
    New-Item -Path $tempIndicatorPath -ItemType File | Out-Null
}

function Ensure-WebAdministration {
    if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
        Write-Warn "Le module 'WebAdministration' n'est pas disponible."
        Write-Info "Installation automatique du rôle IIS Management Scripts and Tools..."
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementScriptingTools -All -NoRestart -ErrorAction Stop
            Write-Success "Le rôle a été installé. Tentative de chargement du module sans redémarrage..."
            $env:PSModulePath = [System.Environment]::GetEnvironmentVariable("PSModulePath","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PSModulePath","User")
            Import-Module WebAdministration -ErrorAction Stop
            Write-Success "Module chargé sans redémarrage."
        } catch {
            Write-ErrorMsg "Le module n'a pas pu être chargé immédiatement. Un redémarrage peut être nécessaire."
            Write-Warn "Si le problème persiste après redémarrage, installez manuellement via les fonctionnalités Windows."
            pause
            exit 0
        }
    } else {
        Import-Module WebAdministration
    }
}

function Test-ModuleInstalled($moduleName) {
    Ensure-WebAdministration
    $modules = Get-WebGlobalModule | Select-Object -ExpandProperty Name
    return $modules -contains $moduleName
}

function Install-UrlRewrite {
    Write-Host "Installation de URL Rewrite..."
    $url = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_fr-FR.msi"
    $msi = "$env:TEMP\rewrite.msi"
    Invoke-WebRequest -Uri $url -OutFile $msi
    Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /quiet"
    Remove-Item $msi
}

function Install-IISNode {
    Write-Host "Installation de IISNode..."
    $url ="https://github.com/azure/iisnode/releases/download/v0.2.21/iisnode-full-v0.2.21-X64.msi"
    $msi = "$env:TEMP\iisnode.msi"
    Invoke-WebRequest -Uri $url -OutFile $msi
    Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /quiet"
    Remove-Item $msi
}

function Install-IISStack {
    # Détection du système d'exploitation
    $osVersion = (Get-CimInstance Win32_OperatingSystem).Caption
    Write-Info "Détection du système : $osVersion"
    Write-Separator

    # Vérification et installation d'IIS
    if ($osVersion -match "Windows Server") {
        if (!(Get-WindowsFeature -Name Web-Server).Installed) {
            Write-Info "Installation d'IIS sur Windows Server..."
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools
            Write-Success "IIS installé sur Windows Server."
        }
        else {
            Write-Success "IIS déjà installé sur Windows Server."
        }
    }
    elseif ($osVersion -match "Windows 11") {
        Write-Info "Vérification d'IIS sur Windows 11..."
        if (!(Get-WindowsOptionalFeature -Online | Where-Object FeatureName -eq "IIS-WebServer").State -eq "Enabled") {
            Write-Info "Installation d'IIS sur Windows 11..."
            dism /online /enable-feature /all /featurename:IIS-WebServer /quiet /norestart
            Write-Success "IIS installé sur Windows 11."
        }
        else {
            Write-Success "IIS déjà installé sur Windows 11."
        }
    }
    else {
        Write-ErrorMsg "Système non pris en charge. Arrêt du script."
        exit 1
    }
    Write-Separator

    # WebAdministration
    Ensure-WebAdministration

    # URL Rewrite
    if (Test-ModuleInstalled "RewriteModule") {
        Write-Success "URL Rewrite déjà installé."
    } else {
        Install-UrlRewrite
        if (Test-ModuleInstalled "RewriteModule") {
            Write-Success "URL Rewrite installé avec succès."
        } else {
            Write-ErrorMsg "Échec de l'installation de URL Rewrite."
        }
    }

    # IISNode
    if (Test-ModuleInstalled "iisnode") {
        Write-Success "IISNode déjà installé."
    } else {
        Install-IISNode
        if (Test-ModuleInstalled "iisnode") {
            Write-Success "IISNode installé avec succès."
        } else {
            Write-ErrorMsg "Échec de l'installation de IISNode."
        }
    }
    Write-Separator
}

#RUN WITH ELEVATION
try {
    # Arrêter le script immédiatement en cas d'erreur
    $ErrorActionPreference = "Stop"

    # Appel unique pour toute la stack IIS
    Install-IISStack

    # Vérifier si Git est disponible
    try {
        $gitVersion = & git --version 2>$null
        if (!$gitVersion) {
            throw "Git n'est pas installé."
        }
        Write-Success "Git déjà installé ($gitVersion)."
    }
    catch {
        
        # URL de téléchargement de Git
        $gitInstallerUrl = "https://github.com/git-for-windows/git/releases/download/v2.49.0.windows.1/Git-2.49.0-64-bit.exe"
        $gitInstallerPath = "$env:TEMP\Git-2.49.0-64-bit.exe"

        # Télécharger le programme d'installation
        Write-Info "📥 Téléchargement de l'installateur Git..."
        Invoke-WebRequest -Uri $gitInstallerUrl -OutFile $gitInstallerPath -ErrorAction Stop -UseBasicParsing | Out-Null
        Write-Success "✅ Téléchargement terminé : $gitInstallerPath"

        # Lancer l'installation silencieuse
        Write-Info "🚀 Installation de Git..."
        Start-Process -FilePath $gitInstallerPath -ArgumentList "/VERYSILENT /NORESTART" -Wait
        Write-Success "✅ Git installé avec succès."

        # Supprimer le fichier d'installation après utilisation
        Remove-Item $gitInstallerPath -Force

    }
    Write-Separator

    # Vérification et installation de Node.js
    try {
        $nodeVersion = & node -v 2>$null
        if ($nodeVersion -notmatch "^v22\..*") {  # Vérifier si la version actuelle est différente de 22
            throw "Node.js n'est pas en version 22."
        }
        Write-Success "Node.js déjà installé ($nodeVersion)."
    }
    catch {
        Write-Warn "Node.js n'est pas détecté ou n'est pas en version 22. Installation en cours..."
        $nodeInstaller = "https://nodejs.org/dist/v22.14.0/node-v22.14.0-x64.msi"
        $nodeInstallerPath = "$env:TEMP\nodejs.msi"
        Write-Info "📥 Téléchargement de l'installateur Node.js..."
        Invoke-WebRequest -Uri $nodeInstaller -OutFile $nodeInstallerPath -ErrorAction Stop -UseBasicParsing | Out-Null
        Write-Success "✅ Téléchargement terminé : $nodeInstallerPath"
        Start-Process -FilePath $nodeInstallerPath -ArgumentList "/quiet" -Wait
        Write-Success "Node.js version 22 installé avec succès !"
    }
    Write-Separator

    # Actualisation des variables d'environnement
    Write-Info "Actualisation des variables d'environnement pour reconnaître npm..."
    $newPath = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Process")
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    $env:Path = $newPath
    Write-Success "Variables d'environnement actualisées."
    Write-Separator

    Write-Warn "Redémarrage du script sans élévation pour la suite..."
    if (-not $SkipRestart) {
        Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -NoRestart -SkipRestart" -NoNewWindow
        exit
    }

}
catch {
    Write-ErrorMsg "Une erreur s'est produite dans la section avec élévation : $_"
    if (Test-Path $tempIndicatorPath) {
        Remove-Item $tempIndicatorPath -Force
    }
    pause
}

# Vérifier si le script doit continuer sans élévation
if ($elevated -and -not $NoRestart -and -not $SkipRestart) {
    Write-Warn "Redémarrage du script sans élévation pour la suite..."
    if (Test-Path $tempIndicatorPath) {
        Remove-Item $tempIndicatorPath -Force
    }
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -NoRestart -SkipRestart" -NoNewWindow
    exit
}

# Configuration IIS
Ensure-WebAdministration

#RUN WITHOUT ELEVATION
try {
    function Test-GitHubConnection {
        Write-Info "`n🔍 Test de connexion à GitHub via SSH..."

        # Vérifier si le dossier .ssh existe, sinon le créer
        $sshFolderPath = "$env:USERPROFILE\.ssh"
        if (!(Test-Path $sshFolderPath)) {
            Write-Info "Création du dossier .ssh..."
            New-Item -ItemType Directory -Path $sshFolderPath | Out-Null
        }

        # Vérifier si github.com est déjà dans known_hosts
        $knownHostsPath = "$sshFolderPath\known_hosts"
        if (!(Test-Path $knownHostsPath)) {
            Write-Info "Ajout de github.com au fichier known_hosts..."
            try {
                # Exécuter ssh-keyscan et ajouter les clés au fichier known_hosts avec l'encodage UTF-8
                $ErrorActionPreference = "Continue"  # Ajustement temporaire pour éviter l'arrêt global
                $keys = ssh-keyscan github.com 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $keys | Out-File -Encoding UTF8 -FilePath $knownHostsPath
                    Write-Success "✅ Clé SSH ajoutée pour github.com."
                }
                else {
                    Write-ErrorMsg "❌ Une erreur s'est produite lors de l'exécution de ssh-keyscan : $keys"
                    Write-ErrorMsg "Vérifiez votre connexion réseau et réessayez."
                    return $false
                }
            }
            catch {
                Write-ErrorMsg "❌ Une erreur inattendue s'est produite lors de l'exécution de ssh-keyscan : $_"
                Write-ErrorMsg "Vérifiez votre connexion réseau et réessayez."
                return $false
            }
            finally {
                $ErrorActionPreference = "Stop"  # Rétablir la préférence d'erreur globale
            }
        }
        else {
            Write-Success "github.com est déjà présent dans le fichier known_hosts."
        }

        try {
            # Exécuter la commande SSH
            $sshTest = ssh -T git@github.com 2>&1

            # Vérifier si le message attendu est retourné
            if ($sshTest -match "successfully authenticated" -or $sshTest -match "does not provide shell access") {
                Write-Success "✅ Connexion SSH à GitHub réussie."
                return $true
            }
            else {
                Write-ErrorMsg "❌ Connexion SSH à GitHub échouée. Message reçu : $sshTest"
                return $false
            }
        }
        catch {
            # Gérer spécifiquement les exceptions générées par SSH
            $errorMessage = $_.Exception.Message
            # Afficher le message d'exception uniquement si la clé SSH existe
            $sshKeyPath = "$env:USERPROFILE\.ssh\kayros_api_rsa"
            if ((Test-Path $sshKeyPath) -and ($errorMessage -match "successfully authenticated" -or $errorMessage -match "does not provide shell access")) {
                Write-Success "✅ Connexion SSH à GitHub réussie malgré l'exception."
                return $true
            }
            elseif (Test-Path $sshKeyPath) {
                Write-ErrorMsg "❌ Une exception s'est produite lors de la connexion à GitHub : $errorMessage"
                Write-ErrorMsg "Vérifiez votre configuration SSH et réessayez."
                return $false
            }
            # Si pas de clé SSH, ne rien afficher de plus
            return $false
        }
    }

    $repoOwner = "I-K-D-S"
    $repoName = "kayros.api"
    $deployKeyUrl = "https://github.com/$repoOwner/$repoName/settings/keys"
    $sshKeyPath = "$env:USERPROFILE\.ssh\kayros_api_rsa"

    if (Test-GitHubConnection) {
        Write-Success "✅ Connexion SSH à GitHub réussie. Pas besoin de générer une nouvelle clé ou d'ajouter des configurations supplémentaires."
    }
    else {
        Write-ErrorMsg "❌ Échec de l'authentification SSH. Génération et configuration d'une clé SSH requise."

        # Création et configuration de la clé SSH
        $sshFolderPath = "$env:USERPROFILE\.ssh"
        if (!(Test-Path $sshFolderPath)) {
            New-Item -ItemType Directory -Path $sshFolderPath | Out-Null
        }

        if (!(Test-Path $sshKeyPath)) {
            Get-Service -Name ssh-agent | Set-Service -StartupType Manual
            Start-Service ssh-agent

            ssh-keygen -t ed25519 -C "bruno.marchasson@gmail.com" -f "$sshKeyPath" -N `"`"
            # ssh-keyscan github.com >> "$env:USERPROFILE\.ssh\known_hosts"
            ssh-add "$sshKeyPath"
            # Ajouter la configuration SSH pour GitHub
            $sshConfigPath = "$sshFolderPath\config"
            if (!(Test-Path $sshConfigPath)) {
                Write-Info "Création du fichier de configuration SSH..."
                New-Item -Path $sshConfigPath -ItemType File -Force | Out-Null
            }

            # Ajouter ou mettre à jour la configuration pour GitHub
            $sshConfigContent = @"
Host github.com
    HostName github.com
    User git
    IdentityFile $sshKeyPath
    IdentitiesOnly yes
"@

            if (!(Get-Content $sshConfigPath | Select-String -Pattern "Host github.com")) {
                Write-Info "Ajout de la configuration SSH pour GitHub dans $sshConfigPath..."
                # Écrire sans BOM
                $sshConfigContent | Set-Content -Path $sshConfigPath -Encoding Ascii
            }
            else {
                Write-Success "La configuration SSH pour GitHub existe déjà dans $sshConfigPath."
            }
        }
        $sshPublicKey = Get-Content "$sshKeyPath.pub"
        # Afficher la clé publique et l'URL
        Write-Info "`n🔑 **Clé SSH publique:**`n$sshPublicKey`n"
        Write-Info "Clé SSH copiée dans le presse-papiers. Vous pouvez la coller sur GitHub.`n"
        Write-Info "`n🌐 **URL GitHub pour l'ajout de la clé:**`n$deployKeyUrl`n"
    
        # Copier la clé publique dans le presse-papiers (nécessite PowerShell 5+)
        $sshPublicKey | Set-Clipboard

        Start-Process $deployKeyUrl

        # Mettre en pause pour ajouter la clé SSH sur GitHub
        Write-Warn "`n🔒 **Ajoutez la clé SSH sur GitHub maintenant.**"
        pause
    }

    # Vérification et gestion du dépôt GitHub
    $targetPath = (Join-Path $PSScriptRoot "kayros.api")  # Utilisation du répertoire du script
    if (!(Test-Path $targetPath)) {
        Write-Info "Clonage du dépôt kayros.api..."
        git clone git@github.com:I-K-D-S/kayros.api.git $targetPath
    }
    elseif ((Get-ChildItem $targetPath -Recurse | Measure-Object).Count -eq 0) {
        Write-Info "Clonage du dépôt kayros.api (dossier vide)..."
        git clone git@github.com:I-K-D-S/kayros.api.git $targetPath
    }
    else {
        Write-Info "Mise à jour du dépôt kayros.api..."
        Push-Location $targetPath
        git reset --hard
        git pull
        Pop-Location
    }
    Write-Separator

    Push-Location $targetPath

    # Check if .env exists, if not, copy from .env.sample and prompt user to edit
    if (!(Test-Path "$targetPath\.env")) {
        Write-Warn ".env n'existe pas. Copie de .env.sample vers .env..."
        Copy-Item "$targetPath\.env.sample" "$targetPath\.env"
        Write-Success ".env créé. Veuillez le configurer."
        
        # Open .env file for user to edit
        Start-Process "$targetPath\.env"

        # Wait for user to finish editing .env
        Write-Warn "Veuillez terminer la configuration de .env et appuyez sur une touche pour continuer..."
        pause
    }
    Write-Separator

    Write-Info "Installation des dépendances avec npm..."
    npm i --force

    Write-Info "Construction du projet avec npm..."
    npm run build
    Pop-Location

    # Add IIS directory to PATH
    $iisPath = Join-Path $env:windir "system32\inetsrv"
    
    # Check if IIS path already exists in the environment variable
    if ($env:Path -notlike "*;$iisPath" -and $env:Path -ne $iisPath) {
        $env:Path += ";$iisPath"
    }

    # Unlock web.config sections
    Write-Info "Déverrouillage des sections web.config..."
    try {
        & appcmd unlock config -section:system.webServer/modules
        & appcmd unlock config -section:system.webServer/handlers
        Write-Success "Sections web.config déverrouillées."
    }
    catch {
        Write-ErrorMsg "Échec du déverrouillage des sections web.config : $_"
    }
    Write-Separator

    
    if (!(Get-Website -Name "kayros.api" -ErrorAction SilentlyContinue)) {
        Write-Info "Création du site IIS kayros.api sur le port 8850..."
        New-WebSite -Name "kayros.api" -Port 8850 -PhysicalPath $targetPath -Force
        Set-ItemProperty "IIS:\Sites\kayros.api" -Name applicationPool -Value "DefaultAppPool"
        Write-Success "Site IIS kayros.api créé."
    } else {
        Write-Success "Site IIS kayros.api déjà existant."
    }

    # Get the application pool identity
    $appPoolName = (Get-Website -Name "kayros.api").applicationPool
    $appPoolIdentity = "IIS APPPOOL\$appPoolName"

    # Grant permissions to the application pool identity on C:\Users\user\Documents
    $documentsPath = "C:\Users\$env:USERNAME\Documents"
    Write-Info "Attribution des permissions au pool d'application '$appPoolIdentity' sur '$documentsPath'..."
    try {
        $acl = Get-Acl -Path $documentsPath
        $permission = "$appPoolIdentity","ReadAndExecute","ContainerInherit, ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $documentsPath -AclObject $acl
        Write-Success "Permissions accordées au pool d'application sur Documents."
    }
    catch {
        Write-ErrorMsg "Échec permissions pool d'application sur Documents : $_"
    }

    # Grant permissions to the application pool identity
    Write-Info "Attribution des permissions au pool d'application '$appPoolIdentity' sur '$targetPath'..."
    try {
        $acl = Get-Acl -Path $targetPath
        $permission = "$appPoolIdentity","Modify, FullControl","ContainerInherit, ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $targetPath -AclObject $acl
        Write-Success "Permissions accordées au pool d'application."
    }
    catch {
        Write-ErrorMsg "Échec permissions pool d'application : $_"
    }

    # Grant IUSR read access
    Write-Info "Attribution des permissions de lecture à IUSR sur '$targetPath'..."
    try {
        $acl = Get-Acl -Path $targetPath
        $permission = "IUSR","Read","ContainerInherit, ObjectInherit","None","Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $targetPath -AclObject $acl
        Write-Success "Permissions accordées à IUSR."
    }
    catch {
        Write-ErrorMsg "Échec permissions IUSR : $_"
    }

    # Restart the website
    Write-Info "Redémarrage du site kayros.api..."
    try {
        Stop-Website -Name "kayros.api"
        Start-Website -Name "kayros.api"
        Write-Success "Site kayros.api redémarré avec succès."
    } catch {
        Write-ErrorMsg "Erreur lors du redémarrage du site : $_"
    }
    Write-Separator

    Write-Success "Déploiement terminé avec succès !"
    if (Test-Path $tempIndicatorPath) {
        Remove-Item $tempIndicatorPath -Force
    }

    # Ouvre le navigateur sur l'URL de test
    $testUrl = "http://localhost:8850/api/hello"
    Write-Info "Ouverture du navigateur sur $testUrl"
    Start-Process $testUrl

    pause
}
catch {
    Write-ErrorMsg "Une erreur s'est produite dans la section sans élévation : $_"
    if (Test-Path $tempIndicatorPath) {
        Remove-Item $tempIndicatorPath -Force
    }
    pause
}