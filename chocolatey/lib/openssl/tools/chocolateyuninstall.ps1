$ErrorActionPreference = 'Stop'
Uninstall-ChocolateyEnvironmentVariable -VariableName OPENSSL_CONF

$path = Get-AppInstallLocation OpenSSL-Win
$pathToRemove = "$path\bin\"
 
foreach ($registryPath in 'hklm:\system\currentcontrolset\control\session manager\environment', 'hkcu:\environment') {
  $p = (Get-Itemproperty -path "$registryPath" -Name Path).Path
  if ("$p" | Select-String -SimpleMatch "$pathToRemove"){
    $newPath = ("$p" -split ';' | ForEach-Object { if (-not ($_ -eq "$pathToRemove")) { $_ } } ) -join ';'
    Set-ItemProperty -path "$registryPath" -Name Path -Value $NewPath
  }
}
