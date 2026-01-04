# Test Challenge Creation Script
$sessionId = "test-session-$(Get-Date -Format 'yyyyMMddHHmmss')"
$body = @{
    message = "create ftp ctf challenge for testing"
    sessionId = $sessionId
} | ConvertTo-Json

Write-Host ""
Write-Host "Testing Challenge Creation..." -ForegroundColor Cyan
Write-Host "Session ID: $sessionId" -ForegroundColor Gray
Write-Host ""
Write-Host "Sending request to backend..." -ForegroundColor Yellow

try {
    # Try CTF automation service directly (port 4003)
    $uri = "http://localhost:4003/api/chat"
    Write-Host "Trying CTF automation service: $uri" -ForegroundColor Gray
    $response = Invoke-RestMethod -Uri $uri -Method POST -Body $body -ContentType "application/json" -TimeoutSec 600
    
    Write-Host ""
    Write-Host "Response received!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Response Summary:" -ForegroundColor Cyan
    Write-Host "Success: $($response.success)" -ForegroundColor $(if($response.success){"Green"}else{"Red"})
    
    if ($response.challenge) {
        Write-Host ""
        Write-Host "Challenge Created:" -ForegroundColor Cyan
        Write-Host "  Name: $($response.challenge.name)" -ForegroundColor White
        Write-Host "  Type: $($response.challenge.type)" -ForegroundColor White
        Write-Host "  Difficulty: $($response.challenge.difficulty)" -ForegroundColor White
    }
    
    if ($response.message) {
        Write-Host ""
        Write-Host "Message:" -ForegroundColor Yellow
        Write-Host $response.message -ForegroundColor White
    }
    
    if ($response.readyForDeployment) {
        Write-Host ""
        Write-Host "Challenge is ready for deployment!" -ForegroundColor Green
        Write-Host "Say yes or deploy to deploy it" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host ""
    Write-Host "Error occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Host ""
        Write-Host "Response Body:" -ForegroundColor Yellow
        Write-Host $responseBody -ForegroundColor Gray
    }
}
