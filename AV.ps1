# Import the necessary module for ZIP functionality
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Function to create a ZIP archive
function Create-Zip {
    param (
        [string]$SourceFolder,
        [string]$DestinationZip
    )
    # Check if the ZIP file already exists
    if (Test-Path $DestinationZip) {
        Remove-Item -Path $DestinationZip -Force
    }
    [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceFolder, $DestinationZip)
}

# Function to check if a process is signed
function Get-SignedStatus {
    param(
        [string]$FilePath
    )

    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath
        return $signature.SignerCertificate -ne $null
    } catch {
        # If an error occurs, assume the file is unsigned
        return $false
    }
}

# Create a temporary directory to store process files
$tempDir = Join-Path -Path $env:TEMP -ChildPath "UnsignedProcesses_$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -ItemType Directory -Path $tempDir | Out-Null

# Get all running processes
$processes = Get-Process | Where-Object { $_.Path -ne $null } # Exclude processes without a valid path

foreach ($process in $processes) {
    $isSigned = Get-SignedStatus -FilePath $process.Path
    if (-not $isSigned) {
        try {
            # Copy the executable file to the temp directory
            $destinationFile = Join-Path -Path $tempDir -ChildPath (Split-Path $process.Path -Leaf)
            Copy-Item -Path $process.Path -Destination $destinationFile -Force -ErrorAction SilentlyContinue
            
            # Log the action
            Write-Output "Saved unsigned process: $($process.Name) (ID: $($process.Id)) to $destinationFile"
            
            # Terminate the process
            Write-Output "Terminating unsigned process: $($process.Name) (ID: $($process.Id))"
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Failed to process $($process.Name): $_"
        }
    }
}

# Create a ZIP archive of the unsigned process files
$zipFile = Join-Path -Path $env:TEMP -ChildPath "UnsignedProcesses.zip"
Create-Zip -SourceFolder $tempDir -DestinationZip $zipFile

# Cleanup temporary folder
Remove-Item -Path $tempDir -Recurse -Force

Write-Output "Unsigned processes saved and terminated. Files are in: $zipFile"
