param(
    [string[]]$SearchPaths = @("C:\"),
    [string[]]$ExcludePaths = @(),
    [switch]$IncludeSensitiveFilenames,
    [switch]$IncludeSpecialFiles,
    [switch]$VerboseOutput,
    [string]$ExportPath,                     
    [ValidateSet("csv", "json", "html", "txt")]
    [string]$ExportFormat
)

# Keywords to search
$keywords = @(
    "password", "pass", "pwd", "passphrase", "login", "logon", "auth", "authenticate",
    "username", "user", "useraccount", "account", "creds", "credentials", "admin", "administrator",
    "apikey", "api_key", "secret", "accesskey", "access_key", "privatekey", "private_key",
    "token", "bearer", "authorization", "auth_token", "clientsecret", "client_secret",
    "dbpassword", "dbpasswd", "dbuser", "dbusername", "dbcredential", "sqlpassword", "mysqlpass",
    "connectionstring", "connstring", "databasepassword", "db_auth", "dbadmin",
    "key", "privatekey", "publickey", "sshkey", "rsa_key", "pgp_key", "encryptionkey", "signingkey",
    "secretkey", "aeskey", "vaultkey", "keystore", "certpassword",
    "aws_secret_access_key", "aws_access_key_id", "azure_secret", "gcp_key", "git_token",
    "jenkins_password", "docker_password", "kubeconfig", "vault_token", "vault_pass",
    "configpassword", "configpass", "adminpass", "rootpass", "masterpassword", "superuser",
    "default_password", "initial_password", "temp_password", "old_password", "new_password"
)

# Sensitive filename patterns
$sensitiveNames = @(
    "pass", "password", "creds", "cred", "login", "secret", "token",
    "auth", "apikey", "jwt", "vault", "key", "config", "env", "connection"
)

# Special files of interest
$specialFiles = @(
    # Credential & Secrets Files
    "unattend.xml", "sysprep.xml", "sysprep.inf", "autounattend.xml",
    "credentials.xml", "cpassword", "*.kdbx", "*.pwd", "*.psafe3", "*.cred",
    "*.rdg", "vault.db", "logins.json", "key3.db", "key4.db", "Local State", "Login Data",

    # Token / API / Config Files
    "secrets.yml", "secrets.yaml", "secrets.json",
    "config.yml", "config.yaml", "config.json", "config.ini",
    ".env", ".env.local", ".env.production",
    "settings.py", "local.settings.json", "appsettings.json",
    "*.pem", "*.key", "*.crt", "*.ovpn",
    "*.ps1", "*.bat", "*.vbs", "*.nupkg",

    "*.xml", "*.ini",

    # Web App Configuration Files
    "web.config", "applicationhost.config", "global.asax", "machine.config",
    "default.aspx", "index.aspx",
    "php.ini", "httpd.conf", "nginx.conf",
    "*.asp", "*.aspx", "*.php", "*.jsp", "*.html",

    # DevOps / Deployment Files
    "docker-compose.yml", "Dockerfile", ".git-credentials", ".npmrc",
    "id_rsa", "id_dsa", "known_hosts", "authorized_keys",
    ".terraformrc", "ansible.cfg", "*.tf", "*.pub",
     
    # AWS, Python config
    ".pypirc", ".boto", "pip.conf", "credentials"  # AWS, Python config

)

Write-Host "[*] Starting sensitive keyword scan..." -ForegroundColor Cyan
Write-Host "[*] Search paths: $($SearchPaths -join ", ")"
if ($ExcludePaths.Count -gt 0) {
    Write-Host "[*] Exclude paths: $($ExcludePaths -join ", ")"
}
if ($IncludeSensitiveFilenames) { Write-Host "[*] Filename pattern matching enabled" }
if ($IncludeSpecialFiles)       { Write-Host "[*] Special file alerting enabled" }
Write-Host ""

$matched = @()

foreach (${path} in $SearchPaths) {
    if (-not (Test-Path ${path})) {
        Write-Host "[-] Path does not exist: ${path}" -ForegroundColor Red
        continue
    }

    Write-Host "`n[*] Scanning path: ${path}"
    $files = Get-ChildItem -Path ${path} -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $exclude = $false
        foreach ($ex in $ExcludePaths) {
            if ($_.FullName -like "$ex*") {
                $exclude = $true
                break
            }
        }
        return -not $exclude
    }

    Write-Host "[*] Files found in ${path}: $($files.Count)"
    $i = 0
    foreach ($file in $files) {
        $i++
        Write-Host -NoNewline "`r[>] Scanning: $($file.FullName.Substring(0, [Math]::Min(80, $file.FullName.Length))) [$i/$($files.Count)]"

        $found = $false

        # Filename check
        if ($IncludeSensitiveFilenames) {
            foreach ($pattern in $sensitiveNames) {
                if ($file.Name -imatch $pattern) {
                    $matched += [PSCustomObject]@{
                        File    = $file.FullName
                        Reason  = "Filename contains '$pattern'"
                    }
                    $found = $true
                    break
                }
            }
        }

        # Special file check
        if ($IncludeSpecialFiles -and !$found) {
            foreach ($spec in $specialFiles) {
                if ($file.Name -like $spec) {
                    $matched += [PSCustomObject]@{
                        File    = $file.FullName
                        Reason  = "Special file match: '$spec'"
                    }
                    $found = $true
                    break
                }
            }
        }

        # Content-based match
        if (-not $found) {
            try {
                $text = Get-Content -Path $file.FullName -ErrorAction Stop -Raw
                foreach ($keyword in $keywords) {
                    if ($text -imatch [regex]::Escape($keyword)) {
                        $matched += [PSCustomObject]@{
                            File    = $file.FullName
                            Reason  = "Keyword match: '$keyword'"
                        }
                        break
                    }
                }
            } catch {
                continue
            }
        }
    }
}

Write-Host "`n`n[+] Scan completed." -ForegroundColor Green
if ($matched.Count -gt 0) {
    Write-Host "[*] Matches found:`n" -ForegroundColor Yellow
    $matched | Sort-Object File | Format-Table -AutoSize

    if ($ExportPath -and $ExportFormat) {
        try {
            switch ($ExportFormat) {
                "csv" {
                    $matched | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
                    Write-Host "[+] Results exported to CSV: $ExportPath" -ForegroundColor Cyan
                }
                "json" {
                    $matched | ConvertTo-Json -Depth 3 | Out-File -FilePath $ExportPath -Encoding UTF8
                    Write-Host "[+] Results exported to JSON: $ExportPath" -ForegroundColor Cyan
                }
                "html" {
                    $matched | ConvertTo-Html | Out-File -FilePath $ExportPath -Encoding UTF8
                    Write-Host "[+] Results exported to HTML: $ExportPath" -ForegroundColor Cyan
                }
                "txt" {
                    $matched | Format-Table -AutoSize | Out-File -FilePath $ExportPath -Encoding UTF8
                    Write-Host "[+] Results exported to TXT: $ExportPath" -ForegroundColor Cyan
                }
            }
        } catch {
            Write-Host "[-] Failed to export results: $_" -ForegroundColor Red
        }
    }
} else {
    Write-Host "[*] No sensitive data matches found." -ForegroundColor DarkGray
}

