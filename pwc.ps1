<#
PowerBuild - Build with MSVC.

MIT License

Copyright (c) 2022 Lmaxplay

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>


function Write-Out {
    param (
        [string]$Text = "",
        [System.ConsoleColor][string]$ForegroundColor = [System.ConsoleColor]::White,
        [switch]$NoNewLine = $false,
        [switch]$Err
    )

    if ($ForegroundColor -in ([System.ConsoleColor]::GetNames([System.ConsoleColor]))) {
        $Color = [System.ConsoleColor]::Parse([System.ConsoleColor], $ForegroundColor)
    } else {
        $Color = $ForegroundColor
    }

    if ($Err) {
        $Color = [System.ConsoleColor]::Red
    }

    if ($Host.Name) {
        Write-Host $Text -NoNewline:$NoNewLine -ForegroundColor $Color
    } else {
        Write-Output $Text
    }
    if ($Err) {
        exit 1
    }
}

$what = $args[0]
if ($null -eq $what) {
    $what = ""
}

#region POWERSHELL_VERSION_CHECK
if ($PSVersionTable.PSVersion.Major -lt 7 -or $PSVersionTable.PSVersion.Minor -lt 2) {
    Write-Out -Error $true "Powershell 7.2 or higher is required, please install from https://aka.ms/pwsh or https://aka.ms/pscore6"
    exit 1
}
#endregion POWERSHELL_VERSION_CHECK

#region CONFIG
$json = Get-Content -Path "pwc.json" -Raw | ConvertFrom-Json

$DEBUG = $json.DEBUG
$ARCH = $json.ARCH
$DLL = $json.DLL
$PROGRAMNAME = $json.PROGRAMNAME
$ENABLED_EXTENSIONS = $json.ENABLED_EXTENSIONS
$AUTOMATICALLY_INCLUDE_ALL_LIBS = $json.AUTOMATICALLY_INCLUDE_ALL_LIBS
$MULTITHREADING = $json.MULTITHREADING

$PROGRAMFILES = $json.PROGRAMFILES
$HOSTARCH = "x64"
if ([System.Environment]::Is64BitProcess -eq $false) {
    $HOSTARCH = "x86"
    if ([System.Environment]::Is64BitOperatingSystem) {
        $PROGRAMFILES = $json.PROGRAMFILES_X86
    }
}

#endregion CONFIG

#region ENVIRONMENT VARIABLES
$env:WindowsSdkDir = "C:\Program Files (x86)\Windows Kits\10"
$env:WindowsSdkVersion = "10.0.22000.0"
# Find latest windows sdk version using C:\Program Files (x86)\Windows Kits\10\bin\, then find the latest version (using get-childitem -directory)
try {
    $WinSDKVersion = (Get-ChildItem -Path "$env:WindowsSdkDir\bin" -Directory | Sort-Object -Property BaseName -Descending | Where-Object { $_.Name -like "10.*" } | Select-Object -First 1).Name
} catch {
    Write-Out -Error $true "Windows SDK not found"
    exit 1
}


$MsvcDir = (Get-ChildItem -Path "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC" -ErrorAction SilentlyContinue -Directory | Sort-Object -Property BaseName -Descending | Select-Object -First 1).FullName
if ($null -eq $MsvcDir) {
    Write-Out -Error $true "MSVC 2022 not found"
    exit 1
}

$msvc = "$MsvcDir\bin\Host$HOSTARCH\$ARCH"

$env:VCToolsInstallDir = "$MsvcDir\Tools\MSVC"

if (-not (Test-Path $msvc)) {
    Write-Out -Error $true "Could not find Command-Line MSVC tools"
    exit 1
}

if (-not ($msvc -in $env:PATH.Split(';'))) {
    Write-Out "Adding $msvc to PATH"
    $env:PATH = "$msvc;$env:PATH"
}

$VkDir = "C:\Program Files\VulkanSDK\1.3.236.0";

#endregion ENVIRONMENT VARIABLES


#region INCLUDES

#region PYTHON_INCLUDE
if ($ENABLED_EXTENSIONS -contains "python") {
    $PyInclude = (Get-ChildItem -Path "$PROGRAMFILES\Python3*" -Directory | Sort-Object -Property BaseName -Descending | Select-Object -First 1).FullName + "\include"
    if ((Test-Path $PyInclude) -eq $false) {
        Write-Out -Error $true "Python include not found"
        exit 1
    }
}
#endregion PYTHON_INCLUDE

#region WINDOWS_INCLUDE

$WinInclude = "$PROGRAMFILES\Windows Kits\10\Include\$WinSDKVersion"

$WINDOWSINCLUDES = @(
    "ucrt",
    "um",
    "shared",
    "winrt",
    "cppwinrt"
)

if ((Test-Path $WinInclude) -eq $false) {
    $WinInclude = "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22000.0"
}

if ((Test-Path $WinInclude) -eq $false) {
    Write-Out -Error $true "Windows include not found"
    exit 1
}

foreach ($dir in $WinLibs) {
    if ((Test-Path "$WinInclude\$dir") -eq $false) {
        Write-Out -Error $true "Windows include not found"
        exit 1
    }
}
#endregion WINDOWS_INCLUDE

#region MSVC_INCLUDE
$MsvcInclude = "$MsvcDir\include"
if ((Test-Path $MsvcInclude) -eq $false) {
    Write-Out -Error $true "MSVC include not found"
    exit 1
}
#endregion MSVC_INCLUDE

#region VK_INCLUDE
if ($ENABLED_EXTENSIONS -contains "vulkan") {
    $VkInclude = "$VkDir\Include"
    if ((Test-Path $VkInclude) -eq $false) {
        Write-Out -Error $true "Vulkan include not found"
        exit 1
    }
}
#endregion VK_INCLUDE

#region GETINCLUDES
<#
.SYNOPSIS
Generates the includes in /I"path" format

.DESCRIPTION
Generates the includes in /I"path" format

.EXAMPLE
Get-Includes

.NOTES
Author: Lmaxplay
#>
function Get-Includes($CPP = $false) {
    $required = @(
        "$MsvcInclude"
    )

    if ($ENABLED_EXTENSIONS -contains "python") {
        $required += "$PyInclude"
    }

    if ($ENABLED_EXTENSIONS -contains "vulkan") {
        $required += "$VkInclude"
    }

    foreach ($dir in $WINDOWSINCLUDES) {
        $required += "$WinInclude\$dir"
    }

    $includes = @()

    foreach ($dir in $required) {
        $includes += "/I`"$dir`""
    }

    if ($debug) {
        Write-Out "Includes: " -ForegroundColor Blue
        foreach ($include in $includes) {
            Write-Out $include -ForegroundColor Blue
        }
    }

    return $includes
}

#endregion GETINCLUDES

#endregion INCLUDES

#region LIBS

#region PYTHON_LIBS
if ($ENABLED_EXTENSIONS -contains "python") {
    $PyLibs = (Get-ChildItem -Path "$PROGRAMFILES\Python3*" -Directory | Sort-Object -Property BaseName -Descending | Select-Object -First 1).FullName + "\libs"
}
#endregion PYTHON_LIBS

#region WINDOWS_LIBS
$WinLib = "$PROGRAMFILES\Windows Kits\10\Lib\$WinSDKVersion"

if ((Test-Path $WinLib) -eq $false) {
    $WinLib = "C:\Program Files (x86)\Windows Kits\10\Lib\$WinSDKVersion"
}

$WinLibs = @(
    "ucrt",
    "ucrt_enclave",
    "um"
)

#endregion WINDOWS_LIBS

#region MSVC_LIBS

$MsvcLibs = "$MsvcDir\lib\$ARCH"

#endregion MSVC_LIBS

#region VK_LIBS
if ($ENABLED_EXTENSIONS -contains "vulkan") {
    $VkLibs = "$VkDir\Lib"
}
#endregion VK_LIBS

#region GETLIBS
<#
.SYNOPSIS
Generates the libs in /LIBPATH:"path" format

.DESCRIPTION
Generates the libs in /LIBPATH:"path" format

.EXAMPLE
Get-Libs

.NOTES
Author: Lmaxplay
#>
function Get-Libs {
    $required = @(
        "$MsvcLibs"
    )

    if ($ENABLED_EXTENSIONS -contains "python") {
        $required += "$PyLibs"
    }

    if ($ENABLED_EXTENSIONS -contains "vulkan") {
        $required += "$VkLibs"
    }

    foreach ($dir in $WinLibs) {
        $required += "$WinLib\$dir\$ARCH"
    }

    $libs = @()

    foreach ($dir in $required) {
        $libs += "/LIBPATH:`"$dir`""
    }
    
    $FORCE_EXCLUDED_LIBFILES = @(
        "BufferOverflow.lib",
        "ucrtd.lib",
        "libucrt.lib",
        "libucrtd.lib",
        "msvcprt.lib"
    )

    $FORCE_EXCLUDED_REGEX = @(
        "clang.*.lib" # Clang libs, we're using MSVC
    )
    
    $libfiles = @()
    if ($AUTOMATICALLY_INCLUDE_ALL_LIBS) {
        foreach ($dir in $required) {
            $locallibfiles += Get-ChildItem -Path "$dir\*.lib" -Recurse | Where-Object {
                $orig = $FORCE_EXCLUDED_LIBFILES -notcontains $_.Name
                if (-not $orig -and $DEBUG) {
                    Write-Out "Excluding $($_.Name) (Force-Exclude)" -ForegroundColor DarkGray
                }
                $regex = $true
                foreach ($regexstr in $FORCE_EXCLUDED_REGEX) {
                    if ($_.Name -match $regexstr) {
                        if ($DEBUG) {
                            Write-Out "Excluding $($_.Name) (Regex `"$regexstr`")" -ForegroundColor DarkGray
                        }
                        $regex = $false
                    }
                }
                $orig -and $regex
            }
            if ($DEBUG) {
                Write-Out "Found $($locallibfiles.Count) lib files in $dir" -ForegroundColor DarkGray
            }
            $libfiles += $locallibfiles
        }
        $libfiles = $libfiles | Select-Object -Unique #| Sort-Object -Property Name # Somehow Sort-Object breaks things

        $libfilesstr = " "
        foreach ($libfile in $libfiles) {
            $libfilesstr += "`"$($libfile.Name)`" "
        }
    }

    if ($DEBUG) {
        Write-Out "Libs: " -ForegroundColor Blue
        foreach ($lib in $libs) {
            Write-Out $lib -ForegroundColor Blue
        }
    }

    return $libs + $libfilesstr
}

#endregion GETLIBS

#endregion LIBS

if ($what -eq "build" -or $what -eq "clean") {
    if ($what -eq "clean") {
        Remove-Item -Path "$PSScriptRoot\build\**" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$PSScriptRoot\out" -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path "$PSScriptRoot\build")) {
        $null = New-Item -ItemType Directory -Path "$PSScriptRoot\build" -Force
    }

    $srcDir = "$PSScriptRoot\src"
    $cFiles = Get-ChildItem -Path $srcDir -Filter "*.c" -Recurse
    $cFiles = $cFiles | Sort-Object -Property FullName
    $cppFiles = Get-ChildItem -Path $srcDir -Include "*.cpp", "*.cxx", "*.cc" -Recurse
    $cppFiles = $cppFiles | Sort-Object -Property FullName

    $files = @()

    if ($null -eq $cFiles) {
        $cFiles = @()
    }
    elseif ($cFiles.GetType().Name -eq "FileInfo") {
        $cFiles = @($cFiles)
    }
    if ($cFiles.Length -gt 0) {
        $s = ""
        if ($cFiles.Length -gt 1) {
            $s = "s"
        }
        Write-Out "Found $($cFiles.Length) C file$s" -ForegroundColor Green
        $files += $cFiles
    }

    if ($null -eq $cppFiles) {
        $cppFiles = @()
    }
    elseif ($cppFiles.GetType().Name -eq "FileInfo") {
        $cppFiles = @($cppFiles)
    }
    if ($cppFiles.Length -gt 0) {
        $s = ""
        if ($cppFiles.Length -gt 1) {
            $s = "s"
        }
        Write-Out "Found $($cppFiles.Length) C++ file$s" -ForegroundColor Green
        $files += $cppFiles
    }

    $objects = @()

    $SystemThreads = 0
    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        $SystemThreads = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    }
    elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
        Write-Out "Failed to get number of logical processors through CIM, resorting to WMI" -ForegroundColor Yellow
        $SystemThreads = (Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors
    }
    else {
        Write-Out "Failed to get number of logical processors through CIM or WMI, resorting to `$env:NUMBER_OF_PROCESSORS"
        $SystemThreads = $env:NUMBER_OF_PROCESSORS
    }

    foreach ($srcFiles in $files) {
        $isCPP = $true

        $objDir = "$PSScriptRoot\build\"
        $objDir = $objDir.Replace("/", "\")

        foreach ($srcFile in $srcFiles) {
            if ($srcFile.Extension -eq ".c") {
                $isCPP = $false
            }

            # Warn if obj file is already in $objects (which means it's a duplicate from a different extension (like .c and .cpp)))
            [System.IO.FileInfo]$srcFile = $srcFile

            $objName = $srcFile.BaseName.Replace($srcDir, $objDir) + ".obj"
            $objName = $objName.Replace("/", "\")
            if ($objects -contains $objName) {
                Write-Out "Warning: Duplicate object file $objName" -ForegroundColor Yellow
            }
            $objects += $objName
        }

        if (-not (Test-Path $objDir)) {
            New-Item -ItemType Directory -Path $objDir -Force
        }

        $cppPart = ""
        if ($isCPP) {
            $cppPart = "/EHsc /TP /std:c++20 /MD"
        }

        $srcFilesString = ""
        foreach ($srcFile in $srcFiles) {
            $srcFilesString += "`"$srcFile`" "
        }

        $MPPart = ""
        if ($MULTITHREADING) {
            $MPPart = "/MP$SystemThreads"
        }

        $cmd = "cl /c $MPPart $cppPart /nologo /O2 /Fo`"$objDir`" $srcFilesString " + ((Get-Includes) -join " ")

        # Write-Out $cmd -ForegroundColor Green
        Invoke-Expression $cmd

        $ErrorCode = $LASTEXITCODE

        # Error checking
        if ($ErrorCode -ne 0) {
            Write-Out -Error $true "Error compiling $srcFiles"
            exit $ErrorCode
        }
    }

    if (-not (Test-Path "$PSScriptRoot\out")) {
        $null = New-Item -ItemType Directory -Path "$PSScriptRoot\out" -Force
    }

    Write-Out -ForegroundColor Green "Linking..."

    $DllArgs = ""
    if ($DLL) {
        $DllArgs = "/DLL /LD"
    }

    $Extension = ""
    if ($DLL) {
        $Extension = "dll"
    }
    else {
        $Extension = "exe"
    }

    $MPPart = ""
    if ($MULTITHREADING) {
        $MPPart = "/MP$SystemThreads"
    }

    if ($AUTOMATICALLY_INCLUDE_ALL_LIBS) {
        Write-Out "Please wait... (Alot of lib files are being included)" -ForegroundColor Yellow
    }

    $cmd = "cl $MPPart $DllArgs /Fe`"$PSScriptRoot\out\$PROGRAMNAME.$Extension`" $objects /link /LIBPATH:`"$PSScriptRoot\build`" /nologo " + ((Get-Libs) -join " ") + " /SUBSYSTEM:CONSOLE"

    # Write-Out $cmd -ForegroundColor Green
    Invoke-Expression $cmd

    Write-Out "Completed" -ForegroundColor Green
}
elseif ($what -eq "sources") {
    $subcommand = $args[1]
    if ($subcommand -eq "libs") {
        $libs = Get-Libs

        Write-Output ($libs -join ";") # Use Write-Output so you can use `$somename = $(./pwc.ps1 sources libs)`
    }
    elseif ($subcommand -eq "includes") {
        $includes = Get-Includes

        Write-Out ($includes -join " ")
    }
    else {
        Write-Out -Error $true "Unknown subcommand `"$subcommand`", expected `"libs`" or `"includes`""
        exit 1
    }
}
elseif ($what -eq 'help') {
    Write-Out "Usage: pwc [build|clean|sources|help] [libs|includes]"
}
elseif ($what -eq '') {
    Write-Out @'
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃             Power-Build             ┃
┃                                     ┃
┃ Build MSVC projects without MSBuild ┃
┃                                     ┃
┃ See "pwc help" for more information ┃
┃   Made by Lmaxplay (Lmaxplay#0001)  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'@ -ForegroundColor Green
}
else {
    $whatr = $what.Replace("\", "\\").Replace("`"", "\`"")
    Write-Out -Error $true "Unknown command `"$whatr`", expected `"build`"`, `"clean`" or `"sources`""
    exit 1
}