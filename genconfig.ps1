# Config here, change this! Then run genconfig.ps1 to generate pwc.json
$DEBUG = $false
$ARCH = "x64"
$PROGRAMFILES = "C:\Program Files"
$PROGRAMFILES_X86 = "C:\Program Files (x86)"
$DLL = $false
$PROGRAMNAME = "example"
$ENABLED_EXTENSIONS = @("vulkan")
$AUTOMATICALLY_INCLUDE_ALL_LIBS = $true
$MULTITHREADING = $true



#--------------------------------------------------



$config = @{
    DEBUG = $DEBUG
    ARCH = $ARCH
    PROGRAMFILES = $PROGRAMFILES
    PROGRAMFILES_X86 = $PROGRAMFILES_X86
    DLL = $DLL
    PROGRAMNAME = $PROGRAMNAME
    ENABLED_EXTENSIONS = $ENABLED_EXTENSIONS
    AUTOMATICALLY_INCLUDE_ALL_LIBS = $AUTOMATICALLY_INCLUDE_ALL_LIBS
    MULTITHREADING = $MULTITHREADING
}
$config | ConvertTo-Json -Depth 100 | Out-File -FilePath "pwc.json"