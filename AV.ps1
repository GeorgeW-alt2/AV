# Import the necessary module for ZIP functionality
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Generate a timestamp for consistent naming
$timestamp = Get-Date -Format 'yyyyMMddHHmmss'

# Define the log file
$logFile = Join-Path -Path $env:TEMP -ChildPath "ProcessLog_$timestamp.log"

# Function to log messages
function Log-Message {
    param(
        [string]$Message
    )
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    $entry | Add-Content -Path $logFile
}

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
$tempDir = Join-Path -Path $env:TEMP -ChildPath "UnsignedProcesses_$timestamp"
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
            Log-Message "Saved unsigned process: $($process.Name) (ID: $($process.Id)) to $destinationFile"
            
            # Terminate the process
            Log-Message "Terminating unsigned process: $($process.Name) (ID: $($process.Id))"
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        } catch {
            Log-Message "Failed to process $($process.Name): $_"
        }
    }
}

# Create a timestamped ZIP file
$zipFile = Join-Path -Path $env:TEMP -ChildPath "UnsignedProcesses_$timestamp.zip"
Create-Zip -SourceFolder $tempDir -DestinationZip $zipFile

# Log the completion
Log-Message "Unsigned processes saved and terminated. Files are in: $zipFile"

# Cleanup temporary folder
Remove-Item -Path $tempDir -Recurse -Force

# Inform the user where the log and ZIP files are located
Write-Output "Process completed. Log file: $logFile"
Write-Output "ZIP file: $zipFile"
