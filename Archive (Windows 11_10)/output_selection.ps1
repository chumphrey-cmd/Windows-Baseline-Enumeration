# Prompt user for output directory, file name, and format
$directoryPath = Read-Host "Please enter the output directory path (e.g., C:\Output)"
$fileName = Read-Host "Please enter the file name (without extension)"

# Prompt user for output format
$validFormats = @(".txt", ".csv", ".md", ".html", ".json", ".xml", ".log")
$formatChoice = Read-Host "Choose an output format (.txt, .csv, .md, .html, .json, .xml, .log)"
while (-not $validFormats -contains $formatChoice) {
    $formatChoice = Read-Host "Invalid format. Choose one of the following: .txt, .csv, .md, .html, .json, .xml, .log"
}

# Join directory, file name, and chosen format
$outputFilePath = Join-Path $directoryPath "$fileName$formatChoice"

# Handle output based on format
if ($formatChoice -eq ".txt") {
    Start-Transcript -Path $outputFilePath -Append
} elseif ($formatChoice -eq ".csv") {
    $csvOutput = @()  # Collect data for CSV export here
    # At the end, export CSV
    $csvOutput | Export-Csv -Path $outputFilePath -NoTypeInformation
} elseif ($formatChoice -eq ".md") {
    Out-File -FilePath $outputFilePath -InputObject "# Windows Baseline Enumeration Report" -Append
    # Add more formatted Markdown text here
} elseif ($formatChoice -eq ".html") {
    $htmlOutput = @()  # Collect data for HTML export here
    # At the end, create HTML content
    $htmlContent = "<html><body><h1>Windows Baseline Enumeration Report</h1>$htmlOutput</body></html>"
    $htmlContent | Out-File -FilePath $outputFilePath
} elseif ($formatChoice -eq ".json") {
    $jsonOutput = @()  # Collect data for JSON export here
    # At the end, export JSON
    $jsonOutput | ConvertTo-Json | Out-File -FilePath $outputFilePath
} elseif ($formatChoice -eq ".xml") {
    $xmlOutput = @()  # Collect data for XML export here
    # At the end, create XML content
    $xmlContent = $xmlOutput | ConvertTo-Xml -NoTypeInformation
    $xmlContent.OuterXml | Out-File -FilePath $outputFilePath
} elseif ($formatChoice -eq ".log") {
    Start-Transcript -Path $outputFilePath -Append
}

# Stop capturing at the end (for .txt and .log transcript)
if ($formatChoice -eq ".txt" -or $formatChoice -eq ".log") {
    Stop-Transcript
}
