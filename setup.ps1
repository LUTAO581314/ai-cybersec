# ai-cybersec one-click environment setup (Windows)
# Usage:  powershell -ExecutionPolicy Bypass -File .\setup.ps1
# What it does:
#   1. Create .venv and install Python deps (mcp / httpx / dnspython)
#   2. Download the latest Nuclei Windows amd64 release into bin\
#   3. Clone nuclei-templates + SecLists(Discovery) + PayloadsAllTheThings into ..\bb-repos\
#   4. Install the bugbounty skill into the global opencode skills dir
#   5. Print the opencode.jsonc MCP snippet to register

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repos = Join-Path (Split-Path $Root -Parent) "bb-repos"
Write-Host "[1/5] Python venv + deps..."
$Py = (Get-Command python -ErrorAction Stop).Source
& $Py -m venv (Join-Path $Root ".venv")
& (Join-Path $Root ".venv\Scripts\python.exe") -m pip install --upgrade pip -q
& (Join-Path $Root ".venv\Scripts\python.exe") -m pip install -r (Join-Path $Root "requirements.txt") -q

Write-Host "[2/5] Nuclei (latest windows/amd64 release)..."
New-Item -ItemType Directory -Path (Join-Path $Root "bin") -Force | Out-Null
Add-Type -AssemblyName System.Net.Http
$handler = [System.Net.Http.HttpClientHandler]::new(); $handler.AllowAutoRedirect = $false
$hc = [System.Net.Http.HttpClient]::new($handler)
$resp = $hc.GetAsync("https://github.com/projectdiscovery/nuclei/releases/latest").Result
$tag = ($resp.Headers.Location.AbsoluteUri -split "/tag/")[-1]
$ver = $tag -replace "^v", ""
$zip = Join-Path $env:TEMP "nuclei_download.zip"
$ProgressPreference = "SilentlyContinue"
Invoke-WebRequest -Uri "https://github.com/projectdiscovery/nuclei/releases/download/$tag/nuclei_${ver}_windows_amd64.zip" -OutFile $zip -UseBasicParsing
Expand-Archive -Path $zip -DestinationPath (Join-Path $Root "bin") -Force
Remove-Item $zip -Force
& (Join-Path $Root "bin\nuclei.exe") -version | Select-Object -First 1

Write-Host "[3/5] Templates + wordlists (cloned once, shared in bb-repos)..."
New-Item -ItemType Directory -Path $Repos -Force | Out-Null
if (-not (Test-Path (Join-Path $Repos "nuclei-templates"))) {
  git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git (Join-Path $Repos "nuclei-templates")
}
if (-not (Test-Path (Join-Path $Repos "SecLists"))) {
  git clone --depth 1 --filter=blob:none --sparse https://github.com/danielmiessler/SecLists.git (Join-Path $Repos "SecLists")
  Set-Location (Join-Path $Repos "SecLists")
  git sparse-checkout set Discovery/DNS Discovery/Web-Content
  Set-Location $Root
}
if (-not (Test-Path (Join-Path $Repos "PayloadsAllTheThings"))) {
  git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git (Join-Path $Repos "PayloadsAllTheThings")
}

Write-Host "[4/5] opencode skill (global)..."
$SkillDst = Join-Path $env:USERPROFILE ".config\opencode\skills\bugbounty"
New-Item -ItemType Directory -Path $SkillDst -Force | Out-Null
Copy-Item (Join-Path $Root ".opencode\skills\bugbounty\SKILL.md") (Join-Path $SkillDst "SKILL.md") -Force

Write-Host "[5/5] Done. Register this in your opencode.jsonc (global config) and restart opencode:"
Write-Host @"

  ""bugbounty"": {
    ""type"": ""local"",
    ""command"": [
      ""$(Join-Path $Root '.venv\Scripts\python.exe')"",
      ""$(Join-Path $Root 'server.py')""
    ],
    ""enabled"": true,
    ""environment"": { ""PYTHONIOENCODING"": ""utf-8"", ""PYTHONUTF8"": ""1"" }
  }
"@
