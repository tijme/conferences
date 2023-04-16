Invoke-WebRequest -Uri https://aka.ms/windbg/download -OutFile c:\windows\temp\windbg.appinstaller
Add-AppxPackage -AppinstallerFile c:\windows\temp\windbg.appinstaller