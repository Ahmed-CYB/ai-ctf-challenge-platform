const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// List of OS images to test for CTF challenges
const osImages = [
  // Linux Distributions
  { name: 'ubuntu', tag: '22.04', description: 'Ubuntu 22.04 LTS - Popular Debian-based Linux' },
  { name: 'ubuntu', tag: '20.04', description: 'Ubuntu 20.04 LTS - Stable Debian-based Linux' },
  { name: 'debian', tag: 'bullseye', description: 'Debian Bullseye - Stable Linux distribution' },
  { name: 'debian', tag: 'bookworm', description: 'Debian Bookworm - Latest stable Debian' },
  { name: 'alpine', tag: 'latest', description: 'Alpine Linux - Minimal lightweight Linux' },
  { name: 'centos', tag: '7', description: 'CentOS 7 - Enterprise Linux (legacy)' },
  { name: 'rockylinux', tag: '9', description: 'Rocky Linux 9 - RHEL-compatible Linux' },
  { name: 'fedora', tag: 'latest', description: 'Fedora - Cutting-edge Linux distribution' },
  { name: 'archlinux', tag: 'latest', description: 'Arch Linux - Rolling release Linux' },
  { name: 'opensuse', tag: 'leap', description: 'openSUSE Leap - Stable SUSE Linux' },
  
  // Specialized/Network-focused
  { name: 'busybox', tag: 'latest', description: 'BusyBox - Minimal Unix utilities' },
  { name: 'phusion/baseimage', tag: 'latest', description: 'Phusion Baseimage - Ubuntu-based with init system' },
  
  // Windows-like (if available)
  { name: 'mcr.microsoft.com/windows/servercore', tag: 'ltsc2022', description: 'Windows Server Core - Windows container' },
  
  // BSD (if available)
  { name: 'freebsd', tag: 'latest', description: 'FreeBSD - BSD Unix system' },
];

const results = [];

async function testImage(imageName, tag, description) {
  const fullName = `${imageName}:${tag}`;
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Testing: ${fullName}`);
  console.log(`Description: ${description}`);
  console.log(`${'='.repeat(80)}`);
  
  const result = {
    image: fullName,
    description,
    valid: false,
    pullable: false,
    runnable: false,
    portsConfigurable: false,
    servicesConfigurable: false,
    size: null,
    osInfo: null,
    packageManager: null,
    errors: []
  };
  
  try {
    // Step 1: Try to pull the image
    console.log(`📥 Pulling ${fullName}...`);
    try {
      const { stdout: pullOutput } = await execAsync(`docker pull ${fullName}`, { timeout: 300000 });
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
      console.error(`❌ Failed to pull ${fullName}: ${pullError.message}`);
      result.errors.push(`Pull failed: ${pullError.message}`);
      results.push(result);
      return result;
    }
    
    // Step 2: Try to run the image
    console.log(`🚀 Testing if image can run...`);
    const testContainerName = `test-${imageName.replace(/[^a-z0-9]/g, '-')}-${Date.now()}`;
    try {
      // Try to run with a simple command
      let runCommand = `docker run --rm --name ${testContainerName} ${fullName}`;
      
      // Different commands for different OS types
      if (imageName.includes('windows') || imageName.includes('mcr.microsoft.com')) {
        runCommand += ` cmd /c "echo test"`;
      } else {
        runCommand += ` sh -c "echo test"`;
      }
      
      const { stdout: runOutput } = await execAsync(runCommand, { timeout: 30000 });
      console.log(`✅ Image can run successfully`);
      result.runnable = true;
    } catch (runError) {
      console.warn(`⚠️  Image may not run with default command: ${runError.message}`);
      result.errors.push(`Run test: ${runError.message}`);
      
      // Try alternative commands
      try {
        const altCommand = `docker run --rm --name ${testContainerName}-alt ${fullName} /bin/sh -c "echo test"`;
        await execAsync(altCommand, { timeout: 30000 });
        console.log(`✅ Image runs with /bin/sh`);
        result.runnable = true;
      } catch (altError) {
        console.warn(`⚠️  Alternative command also failed`);
      }
    }
    
    // Step 3: Check OS information
    console.log(`🔍 Checking OS information...`);
    try {
      let osCommand = `docker run --rm ${fullName}`;
      if (imageName.includes('windows') || imageName.includes('mcr.microsoft.com')) {
        osCommand += ` cmd /c "ver"`;
      } else {
        osCommand += ` sh -c "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || uname -a"`;
      }
      
      const { stdout: osOutput } = await execAsync(osCommand, { timeout: 30000 });
      result.osInfo = osOutput.trim().substring(0, 200);
      console.log(`📋 OS Info: ${result.osInfo.substring(0, 100)}...`);
    } catch (osError) {
      console.warn(`⚠️  Could not get OS info: ${osError.message}`);
    }
    
    // Step 4: Check package manager
    console.log(`📦 Checking package manager...`);
    try {
      let pkgCommand = `docker run --rm ${fullName}`;
      if (imageName.includes('windows') || imageName.includes('mcr.microsoft.com')) {
        result.packageManager = 'Windows (choco/winget)';
      } else {
        pkgCommand += ` sh -c "which apt-get && echo 'apt' || which yum && echo 'yum' || which apk && echo 'apk' || which pacman && echo 'pacman' || which zypper && echo 'zypper' || echo 'unknown'"`;
        const { stdout: pkgOutput } = await execAsync(pkgCommand, { timeout: 30000 });
        result.packageManager = pkgOutput.trim();
      }
      console.log(`📦 Package Manager: ${result.packageManager}`);
    } catch (pkgError) {
      console.warn(`⚠️  Could not detect package manager: ${pkgError.message}`);
    }
    
    // Step 5: Test port configuration
    console.log(`🔌 Testing port configuration...`);
    try {
      const portTestContainer = `port-test-${Date.now()}`;
      const portTestCommand = `docker run -d --name ${portTestContainer} -p 8080:80 ${fullName} sleep 10`;
      await execAsync(portTestCommand, { timeout: 30000 });
      
      // Check if container is running
      const { stdout: psOutput } = await execAsync(`docker ps -a --filter name=${portTestContainer} --format "{{.Status}}"`);
      if (psOutput.trim().includes('Up')) {
        console.log(`✅ Port mapping works (8080:80)`);
        result.portsConfigurable = true;
      }
      
      // Cleanup
      await execAsync(`docker rm -f ${portTestContainer}`, { timeout: 10000 }).catch(() => {});
    } catch (portError) {
      console.warn(`⚠️  Port configuration test failed: ${portError.message}`);
      result.errors.push(`Port test: ${portError.message}`);
    }
    
    // Step 6: Test service installation capability
    console.log(`🛠️  Testing service installation capability...`);
    try {
      let serviceTestCommand = `docker run --rm ${fullName}`;
      if (imageName.includes('windows') || imageName.includes('mcr.microsoft.com')) {
        serviceTestCommand += ` cmd /c "echo Service installation not tested for Windows"`;
        result.servicesConfigurable = true; // Assume yes for Windows
      } else {
        // Try to install a simple service (like netcat)
        serviceTestCommand += ` sh -c "apt-get update -qq && apt-get install -y netcat-openbsd 2>&1 | head -5 || yum install -y nc 2>&1 | head -5 || apk add --no-cache netcat-openbsd 2>&1 | head -5 || echo 'Package manager test'"`;
        const { stdout: serviceOutput } = await execAsync(serviceTestCommand, { timeout: 60000 });
        if (serviceOutput.includes('Setting up') || serviceOutput.includes('Installed') || serviceOutput.includes('OK')) {
          console.log(`✅ Can install services (tested with netcat)`);
          result.servicesConfigurable = true;
        } else {
          console.log(`⚠️  Service installation test inconclusive`);
        }
      }
    } catch (serviceError) {
      console.warn(`⚠️  Service installation test failed: ${serviceError.message}`);
      result.errors.push(`Service test: ${serviceError.message}`);
    }
    
    // Mark as valid if it passed basic tests
    result.valid = result.pullable && result.runnable;
    
  } catch (error) {
    console.error(`❌ Error testing ${fullName}: ${error.message}`);
    result.errors.push(`General error: ${error.message}`);
  }
  
  results.push(result);
  return result;
}

async function main() {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`Docker OS Image Testing for CTF Challenges`);
  console.log(`Testing ${osImages.length} images...`);
  console.log(`${'='.repeat(80)}\n`);
  
  for (const image of osImages) {
    await testImage(image.name, image.tag, image.description);
    // Small delay between tests
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  // Print summary
  console.log(`\n${'='.repeat(80)}`);
  console.log(`SUMMARY`);
  console.log(`${'='.repeat(80)}\n`);
  
  const validImages = results.filter(r => r.valid);
  const pullableImages = results.filter(r => r.pullable);
  const configurableImages = results.filter(r => r.portsConfigurable && r.servicesConfigurable);
  
  console.log(`Total images tested: ${results.length}`);
  console.log(`✅ Valid images: ${validImages.length}`);
  console.log(`📥 Pullable images: ${pullableImages.length}`);
  console.log(`🔧 Fully configurable (ports + services): ${configurableImages.length}\n`);
  
  console.log(`\n📋 DETAILED RESULTS:\n`);
  results.forEach((result, index) => {
    console.log(`${index + 1}. ${result.image}`);
    console.log(`   Description: ${result.description}`);
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
    if (result.errors.length > 0) {
      console.log(`   Errors: ${result.errors.join('; ')}`);
    }
    console.log('');
  });
  
  // Save results to JSON
  const fs = require('fs');
  fs.writeFileSync('os-image-test-results.json', JSON.stringify(results, null, 2));
  console.log(`\n💾 Results saved to os-image-test-results.json\n`);
}

main().catch(console.error);

