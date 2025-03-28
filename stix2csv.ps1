param (
    [Parameter(Mandatory = $true)]
    [string]$InputFolder,

    [Parameter(Mandatory = $true)]
    [string]$OutputFile
)

# Set expiration timestamp (48 hours from now)
$expiration = (Get-Date).AddHours(48).ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
$allRecords = @()

# Regex for STIX pattern parsing
$patternRegex = "\[(\w+):value\s*=\s*'([^']+)'\]"

# Get all JSON files in the input folder
$InputFiles = Get-ChildItem -Path $InputFolder -Filter *.json -File | Select-Object -ExpandProperty FullName

Write-Host "Found $($InputFiles.Count) JSON file(s) in folder: $InputFolder"

foreach ($InputFile in $InputFiles) {
    Write-Host "Processing: $InputFile"

    try {
        $json = Get-Content $InputFile -Raw | ConvertFrom-Json
    } catch {
        Write-Warning "Failed to parse ${InputFile}: $_"
        continue
    }

    if (-not $json.objects) {
        Write-Warning "No 'objects' array found in: ${InputFile}"
        continue
    }

    foreach ($obj in $json.objects) {
        switch ($obj.type) {
            "ipv4-addr" {
                $allRecords += [PSCustomObject]@{
                    IndicatorType        = "IpAddress"
                    IndicatorValue       = $obj.value
                    ExpirationTime       = $expiration
                    Action               = "Block"
                    Severity             = "High"
                    Title                = "Imported STIX IP"
                    Description          = "Imported from ${InputFile}"
                    RecommendedActions   = ""
                    RbacGroups           = ""
                    Category             = ""
                    MitreTechniques      = ""
                    GenerateAlert        = "TRUE"
                }
            }
            "url" {
                $allRecords += [PSCustomObject]@{
                    IndicatorType        = "Url"
                    IndicatorValue       = $obj.value
                    ExpirationTime       = $expiration
                    Action               = "Block"
                    Severity             = "High"
                    Title                = "Imported STIX URL"
                    Description          = "Imported from ${InputFile}"
                    RecommendedActions   = ""
                    RbacGroups           = ""
                    Category             = ""
                    MitreTechniques      = ""
                    GenerateAlert        = "TRUE"
                }
            }
            "domain-name" {
                $allRecords += [PSCustomObject]@{
                    IndicatorType        = "DomainName"
                    IndicatorValue       = $obj.value
                    ExpirationTime       = $expiration
                    Action               = "Block"
                    Severity             = "High"
                    Title                = "Imported STIX Domain"
                    Description          = "Imported from ${InputFile}"
                    RecommendedActions   = ""
                    RbacGroups           = ""
                    Category             = ""
                    MitreTechniques      = ""
                    GenerateAlert        = "TRUE"
                }
            }
            "file" {
                if ($obj.hashes.'SHA-1') {
                    $allRecords += [PSCustomObject]@{
                        IndicatorType        = "FileSha1"
                        IndicatorValue       = $obj.hashes.'SHA-1'
                        ExpirationTime       = $expiration
                        Action               = "Block"
                        Severity             = "High"
                        Title                = "Imported STIX File SHA1"
                        Description          = "Imported from ${InputFile}"
                        RecommendedActions   = ""
                        RbacGroups           = ""
                        Category             = ""
                        MitreTechniques      = ""
                        GenerateAlert        = "TRUE"
                    }
                }
                if ($obj.hashes.'SHA-256') {
                    $allRecords += [PSCustomObject]@{
                        IndicatorType        = "FileSha256"
                        IndicatorValue       = $obj.hashes.'SHA-256'
                        ExpirationTime       = $expiration
                        Action               = "Block"
                        Severity             = "High"
                        Title                = "Imported STIX File SHA256"
                        Description          = "Imported from ${InputFile}"
                        RecommendedActions   = ""
                        RbacGroups           = ""
                        Category             = ""
                        MitreTechniques      = ""
                        GenerateAlert        = "TRUE"
                    }
                }
            }
            "indicator" {
                if ($obj.pattern -match $patternRegex) {
                    $stixType = $matches[1]
                    $indicatorValue = $matches[2]

                    $mappedType = switch ($stixType) {
                        "ipv4-addr"   { "IpAddress" }
                        "url"         { "Url" }
                        "domain-name" { "DomainName" }
                        "file"        { "FileSha1" }  # Default for file pattern
                        default       { $null }
                    }

                    if ($mappedType) {
                        $allRecords += [PSCustomObject]@{
                            IndicatorType        = $mappedType
                            IndicatorValue       = $indicatorValue
                            ExpirationTime       = $expiration
                            Action               = "Block"
                            Severity             = "High"
                            Title                = "Imported STIX Indicator"
                            Description          = "Extracted from pattern in ${InputFile}"
                            RecommendedActions   = ""
                            RbacGroups           = ""
                            Category             = ""
                            MitreTechniques      = ""
                            GenerateAlert        = "TRUE"
                        }
                    }
                }
            }
        }
    }
}

# Export to CSV
if ($allRecords.Count -eq 0) {
    Write-Warning "No indicators found in any file."
    exit 1
}

$allRecords | Export-Csv -Path $OutputFile -NoTypeInformation
Write-Host "Exported $($allRecords.Count) indicators to: $OutputFile"
