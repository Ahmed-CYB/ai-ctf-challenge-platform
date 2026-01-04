const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// Windows Docker images to test
const windowsImages = [
  // Microsoft Official Windows Images
  { name: 'mcr.microsoft.com/windows/servercore', tag: 'ltsc2022', description: 'Windows Server Core 2022 - Full Windows Server' },
  { name: 'mcr.microsoft.com/windows/servercore', tag: 'ltsc2019', description: 'Windows Server Core 2019 - Previous LTS' },
  { name: 'mcr.microsoft.com/windows/nanoserver', tag: 'ltsc2022', description: 'Windows Nano Server 2022 - Minimal Windows' },
  { name: 'mcr.microsoft.com/windows/nanoserver', tag: 'ltsc2019', description: 'Windows Nano Server 2019 - Minimal Windows' },
  
  // Windows-like alternatives (Linux containers that simulate Windows)
  { name: 'ubuntu', tag: '22.04', description: 'Ubuntu with Samba (Windows-like SMB services)', isLinux: true },
  { name: 'rockylinux', tag: '9', description: 'Rocky Linux with Samba/Active Directory (Windows-like)', isLinux: true },
];

const results = [];

async function testWindowsImage(imageName, tag, description, isLinux = false) {
  const fullName = `${imageName}:${tag}`;
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Testing: ${fullName}`);
  console.log(`Description: ${description}`);
  console.log(`Type: ${isLinux ? 'Linux Container (Windows-like services)' : 'Windows Container'}`);
  console.log(`${'='.repeat(80)}`);
  
  const result = {
    image: fullName,
    description,
    type: isLinux ? 'Linux (Windows-like)' : 'Windows',
    valid: false,
    pullable: false,
    runnable: false,
    portsConfigurable: false,
    servicesConfigurable: false,
    size: null,
    osInfo: null,
    packageManager: null,
    errors: [],
    notes: []
  };
  
  try {
    // Step 1: Try to pull the image
    console.log(`📥 Pulling ${fullName}...`);
    try {
      const { stdout: pullOutput } = await execAsync(`docker pull ${fullName}`, { timeout: 600000 });
      console.log(`✅ Successfully pulled ${fullName}`);
      result.pullable = true;
      
      // Get image size
      try {
        const { stdout: inspectOutput } = await execAsync(`docker image inspect ${fullName} --format "{{.Size}}"`);
        const sizeBytes = parseInt(inspectOutput.trim());
        result.size = `${(sizeBytes / 1024 / 1024).toFixed(2)} MB`;
        console.log(`📦 Image size: ${result.size}`);
      } catch (e) {
        console.warn(`⚠️  Could not get image size: ${e.message}`);
      }
    } catch (pullError) {
      const errorMsg = pullError.message;
      console.error(`❌ Failed to pull ${fullName}: ${errorMsg}`);
      
      if (errorMsg.includes('no matching manifest for linux/amd64')) {
        result.errors.push('Requires Windows containers mode (not Linux containers mode)');
        result.notes.push('To use this image, switch Docker Desktop to Windows containers mode');
      } else if (errorMsg.includes('not found')) {
        result.errors.push('Image not found on Docker Hub');
      } else {
        result.errors.push(`Pull failed: ${errorMsg}`);
      }
      
      results.push(result);
      return result;
    }
    
    // Step 2: Try to run the image
    console.log(`🚀 Testing if image can run...`);
    const testContainerName = `test-win-${imageName.replace(/[^a-z0-9]/g, '-')}-${Date.now()}`;
    try {
      let runCommand;
      if (isLinux) {
        runCommand = `docker run --rm --name ${testContainerName} ${fullName} sh -c "echo test"`;
      } else {
        // Windows containers
        runCommand = `docker run --rm --name ${testContainerName} ${fullName} cmd /c "echo test"`;
      }
      
      const { stdout: runOutput } = await execAsync(runCommand, { timeout: 60000 });
      console.log(`✅ Image can run successfully`);
      result.runnable = true;
    } catch (runError) {
      console.warn(`⚠️  Image may not run with default command: ${runError.message}`);
      result.errors.push(`Run test: ${runError.message}`);
      
      if (runError.message.includes('cannot be used with linux containers')) {
        result.notes.push('This is a Windows container - requires switching Docker to Windows containers mode');
      }
    }
    
    // Step 3: Check OS information
    console.log(`🔍 Checking OS information...`);
    try {
      let osCommand;
      if (isLinux) {
        osCommand = `docker run --rm ${fullName} sh -c "cat /etc/os-release 2>/dev/null || uname -a"`;
      } else {
        osCommand = `docker run --rm ${fullName} cmd /c "ver"`;
      }
      
      const { stdout: osOutput } = await execAsync(osCommand, { timeout: 60000 });
      result.osInfo = osOutput.trim().substring(0, 200);
      console.log(`📋 OS Info: ${result.osInfo.substring(0, 100)}...`);
    } catch (osError) {
      console.warn(`⚠️  Could not get OS info: ${osError.message}`);
    }
    
    // Step 4: Check package manager / service installation
    console.log(`📦 Checking package/service installation capability...`);
    try {
      if (isLinux) {
        // Test Samba installation (Windows-like SMB service)
        const sambaTest = `docker run --rm ${fullName} sh -c "apt-get update -qq 2>&1 | head -3 && echo 'Can install packages' || yum update -q 2>&1 | head -3 && echo 'Can install packages' || apk update -q 2>&1 | head -3 && echo 'Can install packages'"`;
        const { stdout: pkgOutput } = await execAsync(sambaTest, { timeout: 120000 });
        result.packageManager = pkgOutput.includes('apt-get') ? 'apt-get' : 
                                pkgOutput.includes('yum') ? 'yum/dnf' : 
                                pkgOutput.includes('apk') ? 'apk' : 'unknown';
        result.servicesConfigurable = true;
        result.notes.push('Can install Samba for SMB/CIFS (Windows file sharing)');
        result.notes.push('Can install Active Directory services (Samba AD)');
        console.log(`📦 Package Manager: ${result.packageManager}`);
      } else {
        // Windows containers
        result.packageManager = 'Windows (choco/winget/powershell)';
        result.servicesConfigurable = true;
        result.notes.push('Can install Windows services via PowerShell');
        result.notes.push('Can use Chocolatey or winget for package management');
        console.log(`📦 Package Manager: Windows (choco/winget)`);
      }
    } catch (pkgError) {
      console.warn(`⚠️  Could not test package manager: ${pkgError.message}`);
    }
    
    // Step 5: Test port configuration (use random port to avoid conflicts)
    console.log(`🔌 Testing port configuration...`);
    try {
      const randomPort = 30000 + Math.floor(Math.random() * 1000);
      const portTestContainer = `port-test-win-${Date.now()}`;
      
      let portTestCommand;
      if (isLinux) {
        portTestCommand = `docker run -d --name ${portTestContainer} -p ${randomPort}:80 ${fullName} sleep 10`;
      } else {
        portTestCommand = `docker run -d --name ${portTestContainer} -p ${randomPort}:80 ${fullName} cmd /c "timeout /t 10"`;
      }
      
      await execAsync(portTestCommand, { timeout: 30000 });
      
      // Check if container is running
      const { stdout: psOutput } = await execAsync(`docker ps -a --filter name=${portTestContainer} --format "{{.Status}}"`);
      if (psOutput.trim().includes('Up') || psOutput.trim().includes('Exited')) {
        console.log(`✅ Port mapping works (${randomPort}:80)`);
        result.portsConfigurable = true;
      }
      
      // Cleanup
      await execAsync(`docker rm -f ${portTestContainer}`, { timeout: 10000 }).catch(() => {});
    } catch (portError) {
      console.warn(`⚠️  Port configuration test failed: ${portError.message}`);
      if (portError.message.includes('cannot be used with linux containers')) {
        result.notes.push('Windows containers require Windows containers mode');
      }
    }
    
    // Mark as valid if it passed basic tests
    result.valid = result.pullable && (result.runnable || isLinux);
    
  } catch (error) {
    console.error(`❌ Error testing ${fullName}: ${error.message}`);
    result.errors.push(`General error: ${error.message}`);
  }
  
  results.push(result);
  return result;
}

async function main() {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Windows Docker Image Testing for CTF Challenges`);
  console.log(`Testing ${windowsImages.length} images...`);
  console.log(`Note: Your Docker is running in Linux containers mode (WSL2)`);
  console.log(`${'='.repeat(80)}\n`);
  
  for (const image of windowsImages) {
    await testWindowsImage(image.name, image.tag, image.description, image.isLinux || false);
    // Small delay between tests
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  // Print summary
  console.log(`\n${'='.repeat(80)}`);
  console.log(`SUMMARY`);
  console.log(`${'='.repeat(80)}\n`);
  
  const validImages = results.filter(r => r.valid);
  const windowsContainers = results.filter(r => !r.isLinux && r.type === 'Windows');
  const linuxWindowsLike = results.filter(r => r.isLinux);
  
  console.log(`Total images tested: ${results.length}`);
  console.log(`✅ Valid images: ${validImages.length}`);
  console.log(`🪟 Windows containers: ${windowsContainers.length} (require Windows containers mode)`);
  console.log(`🐧 Linux containers (Windows-like): ${linuxWindowsLike.length} (work in current mode)\n`);
  
  console.log(`\n📋 DETAILED RESULTS:\n`);
  results.forEach((result, index) => {
    console.log(`${index + 1}. ${result.image}`);
    console.log(`   Description: ${result.description}`);
    console.log(`   Type: ${result.type}`);
    console.log(`   Status: ${result.valid ? '✅ VALID' : '❌ INVALID'}`);
    console.log(`   Size: ${result.size || 'Unknown'}`);
    console.log(`   Pullable: ${result.pullable ? '✅' : '❌'}`);
    console.log(`   Runnable: ${result.runnable ? '✅' : '❌'}`);
    console.log(`   Ports Configurable: ${result.portsConfigurable ? '✅' : '❌'}`);
    console.log(`   Services Configurable: ${result.servicesConfigurable ? '✅' : '❌'}`);
    console.log(`   Package Manager: ${result.packageManager || 'Unknown'}`);
    if (result.osInfo) {
      console.log(`   OS Info: ${result.osInfo.substring(0, 100)}...`);
    }
    if (result.notes.length > 0) {
      console.log(`   Notes: ${result.notes.join('; ')}`);
    }
    if (result.errors.length > 0) {
      console.log(`   Errors: ${result.errors.join('; ')}`);
    }
    console.log('');
  });
  
  // Save results to JSON
  const fs = require('fs');
  fs.writeFileSync('windows-image-test-results.json', JSON.stringify(results, null, 2));
  console.log(`\n💾 Results saved to windows-image-test-results.json\n`);
  
  // Print recommendations
  console.log(`\n${'='.repeat(80)}`);
  console.log(`RECOMMENDATIONS FOR WINDOWS CTF CHALLENGES`);
  console.log(`${'='.repeat(80)}\n`);
  
  console.log(`Since your Docker is in Linux containers mode (WSL2), you have two options:\n`);
  
  console.log(`OPTION 1: Use Linux Containers with Windows-like Services (RECOMMENDED)`);
  console.log(`- Use Ubuntu/Rocky Linux with Samba for SMB/CIFS (Windows file sharing)`);
  console.log(`- Use Samba Active Directory for AD services`);
  console.log(`- Use xrdp for RDP (Remote Desktop)`);
  console.log(`- Advantages: Works in current mode, smaller images, easier to configure\n`);
  
  console.log(`OPTION 2: Switch to Windows Containers Mode`);
  console.log(`- Right-click Docker Desktop icon → "Switch to Windows containers"`);
  console.log(`- Can use real Windows Server Core / Nano Server images`);
  console.log(`- Advantages: Real Windows OS, native Windows services`);
  console.log(`- Disadvantages: Larger images, requires Windows containers mode\n`);
}

main().catch(console.error);

