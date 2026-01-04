/**
 * OS Image Testing Script
 * Tests multiple Docker OS images for CTF challenge compatibility
 * Checks: validity, port configuration, service installation
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

// OS images to test
const OS_IMAGES = [
  // Linux Distributions
  { name: 'Ubuntu 22.04', image: 'ubuntu:22.04', packageManager: 'apt', osType: 'linux' },
  { name: 'Ubuntu 20.04', image: 'ubuntu:20.04', packageManager: 'apt', osType: 'linux' },
  { name: 'Debian 12', image: 'debian:12', packageManager: 'apt', osType: 'linux' },
  { name: 'Debian 11', image: 'debian:11', packageManager: 'apt', osType: 'linux' },
  { name: 'Alpine 3.19', image: 'alpine:3.19', packageManager: 'apk', osType: 'linux' },
  { name: 'Alpine 3.18', image: 'alpine:3.18', packageManager: 'apk', osType: 'linux' },
  { name: 'CentOS 7', image: 'centos:7', packageManager: 'yum', osType: 'linux' },
  { name: 'Fedora 39', image: 'fedora:39', packageManager: 'dnf', osType: 'linux' },
  { name: 'Rocky Linux 9', image: 'rockylinux:9', packageManager: 'dnf', osType: 'linux' },
  { name: 'Arch Linux', image: 'archlinux:latest', packageManager: 'pacman', osType: 'linux' },
  { name: 'Kali Linux', image: 'kalilinux/kali-rolling', packageManager: 'apt', osType: 'linux' },
  
  // Minimal/BusyBox
  { name: 'BusyBox', image: 'busybox:latest', packageManager: 'none', osType: 'linux' },
  
  // Note: Windows images require Windows containers (not tested here)
];

const TEST_RESULTS = [];

/**
 * Test if Docker image exists and can be pulled
 */
async function testImagePull(imageName) {
  try {
    console.log(`\n📥 Pulling ${imageName}...`);
    const { stdout, stderr } = await execAsync(`docker pull ${imageName}`, { timeout: 300000 });
    
    if (stderr && !stderr.includes('Downloaded') && !stderr.includes('Already exists')) {
      console.warn(`⚠️  Warning during pull: ${stderr}`);
    }
    
    // Verify image exists
    const { stdout: inspectOut } = await execAsync(`docker image inspect ${imageName}`, { timeout: 10000 });
    const imageInfo = JSON.parse(inspectOut)[0];
    
    return {
      success: true,
      size: imageInfo.Size,
      architecture: imageInfo.Architecture,
      os: imageInfo.Os,
      created: imageInfo.Created
    };
  } catch (error) {
    console.error(`❌ Failed to pull ${imageName}: ${error.message}`);
    return { success: false, error: error.message };
  }
}

/**
 * Test if container can be started
 */
async function testContainerStart(imageName, containerName) {
  try {
    // Clean up any existing container
    try {
      await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    } catch (e) {
      // Ignore if container doesn't exist
    }
    
    console.log(`🚀 Starting container ${containerName}...`);
    const { stdout } = await execAsync(
      `docker run -d --name ${containerName} ${imageName} sleep 300`,
      { timeout: 30000 }
    );
    
    // Wait a moment for container to start
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Check if container is running
    const { stdout: statusOut } = await execAsync(`docker ps --filter name=${containerName} --format "{{.Status}}"`, { timeout: 5000 });
    
    return {
      success: statusOut.trim().length > 0,
      containerId: stdout.trim()
    };
  } catch (error) {
    console.error(`❌ Failed to start container: ${error.message}`);
    return { success: false, error: error.message };
  } finally {
    // Cleanup
    try {
      await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    } catch (e) {
      // Ignore cleanup errors
    }
  }
}

/**
 * Test port configuration
 */
async function testPortConfiguration(imageName, containerName) {
  try {
    console.log(`🔌 Testing port configuration...`);
    
    // Start container with port mapping
    try {
      await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    } catch (e) {}
    
    const { stdout } = await execAsync(
      `docker run -d --name ${containerName} -p 8080:80 ${imageName} sleep 300`,
      { timeout: 30000 }
    );
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Check if port mapping is active
    const { stdout: portOut } = await execAsync(
      `docker port ${containerName}`,
      { timeout: 5000 }
    );
    
    const portsConfigured = portOut.includes('80/tcp');
    
    // Cleanup
    await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    
    return {
      success: portsConfigured,
      portMapping: portOut.trim()
    };
  } catch (error) {
    console.error(`❌ Port configuration test failed: ${error.message}`);
    try {
      await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    } catch (e) {}
    return { success: false, error: error.message };
  }
}

/**
 * Test service installation capability
 */
async function testServiceInstallation(imageName, containerName, packageManager) {
  if (packageManager === 'none') {
    return { success: false, error: 'No package manager available' };
  }
  
  try {
    console.log(`📦 Testing service installation (${packageManager})...`);
    
    // Start container
    try {
      await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    } catch (e) {}
    
    const { stdout } = await execAsync(
      `docker run -d --name ${containerName} ${imageName} sleep 300`,
      { timeout: 30000 }
    );
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Test installing a simple package
    let installCommand;
    let testPackage = 'curl'; // Common package available in most distros
    
    switch (packageManager) {
      case 'apt':
        installCommand = `docker exec ${containerName} bash -c "apt-get update && apt-get install -y ${testPackage}"`;
        break;
      case 'apk':
        installCommand = `docker exec ${containerName} sh -c "apk update && apk add ${testPackage}"`;
        break;
      case 'yum':
        installCommand = `docker exec ${containerName} bash -c "yum install -y ${testPackage}"`;
        break;
      case 'dnf':
        installCommand = `docker exec ${containerName} bash -c "dnf install -y ${testPackage}"`;
        break;
      case 'pacman':
        installCommand = `docker exec ${containerName} bash -c "pacman -Sy --noconfirm ${testPackage}"`;
        break;
      default:
        return { success: false, error: `Unknown package manager: ${packageManager}` };
    }
    
    const { stdout: installOut, stderr: installErr } = await execAsync(
      installCommand,
      { timeout: 120000 }
    );
    
    // Verify package was installed
    let verifyCommand;
    switch (packageManager) {
      case 'apt':
      case 'yum':
      case 'dnf':
        verifyCommand = `docker exec ${containerName} which ${testPackage}`;
        break;
      case 'apk':
        verifyCommand = `docker exec ${containerName} which ${testPackage}`;
        break;
      case 'pacman':
        verifyCommand = `docker exec ${containerName} which ${testPackage}`;
        break;
    }
    
    const { stdout: verifyOut } = await execAsync(verifyCommand, { timeout: 10000 });
    const packageInstalled = verifyOut.trim().length > 0;
    
    // Cleanup
    await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    
    return {
      success: packageInstalled,
      packageManager,
      testPackage,
      installOutput: installOut.substring(0, 200) // First 200 chars
    };
  } catch (error) {
    console.error(`❌ Service installation test failed: ${error.message}`);
    try {
      await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    } catch (e) {}
    return { success: false, error: error.message };
  }
}

/**
 * Test SSH service installation (common for CTF challenges)
 */
async function testSSHInstallation(imageName, containerName, packageManager) {
  if (packageManager === 'none') {
    return { success: false, error: 'No package manager available' };
  }
  
  try {
    console.log(`🔐 Testing SSH service installation...`);
    
    // Start container
    try {
      await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    } catch (e) {}
    
    const { stdout } = await execAsync(
      `docker run -d --name ${containerName} ${imageName} sleep 300`,
      { timeout: 30000 }
    );
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Install SSH server
    let installCommand;
    const sshPackage = packageManager === 'apk' ? 'openssh' : 'openssh-server';
    
    switch (packageManager) {
      case 'apt':
        installCommand = `docker exec ${containerName} bash -c "apt-get update && apt-get install -y ${sshPackage}"`;
        break;
      case 'apk':
        installCommand = `docker exec ${containerName} sh -c "apk update && apk add ${sshPackage}"`;
        break;
      case 'yum':
        installCommand = `docker exec ${containerName} bash -c "yum install -y ${sshPackage}"`;
        break;
      case 'dnf':
        installCommand = `docker exec ${containerName} bash -c "dnf install -y ${sshPackage}"`;
        break;
      case 'pacman':
        installCommand = `docker exec ${containerName} bash -c "pacman -Sy --noconfirm ${sshPackage}"`;
        break;
    }
    
    await execAsync(installCommand, { timeout: 120000 });
    
    // Verify SSH is available
    const { stdout: verifyOut } = await execAsync(
      `docker exec ${containerName} which sshd || docker exec ${containerName} which ssh`,
      { timeout: 10000 }
    );
    
    const sshAvailable = verifyOut.trim().length > 0;
    
    // Cleanup
    await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    
    return {
      success: sshAvailable,
      sshPackage
    };
  } catch (error) {
    console.error(`❌ SSH installation test failed: ${error.message}`);
    try {
      await execAsync(`docker rm -f ${containerName}`, { timeout: 5000 });
    } catch (e) {}
    return { success: false, error: error.message };
  }
}

/**
 * Main test function
 */
async function testOSImage(osConfig) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`🧪 Testing: ${osConfig.name}`);
  console.log(`   Image: ${osConfig.image}`);
  console.log(`   Package Manager: ${osConfig.packageManager}`);
  console.log(`${'='.repeat(60)}`);
  
  const containerName = `test-${osConfig.image.replace(/[^a-z0-9]/gi, '-').toLowerCase()}`;
  
  const result = {
    name: osConfig.name,
    image: osConfig.image,
    packageManager: osConfig.packageManager,
    osType: osConfig.osType,
    tests: {}
  };
  
  // Test 1: Image Pull
  result.tests.pull = await testImagePull(osConfig.image);
  
  if (!result.tests.pull.success) {
    result.overall = 'FAILED';
    result.reason = 'Image pull failed';
    return result;
  }
  
  // Test 2: Container Start
  result.tests.containerStart = await testContainerStart(osConfig.image, containerName);
  
  if (!result.tests.containerStart.success) {
    result.overall = 'FAILED';
    result.reason = 'Container start failed';
    return result;
  }
  
  // Test 3: Port Configuration
  result.tests.portConfig = await testPortConfiguration(osConfig.image, containerName);
  
  // Test 4: Service Installation
  result.tests.serviceInstall = await testServiceInstallation(
    osConfig.image,
    containerName,
    osConfig.packageManager
  );
  
  // Test 5: SSH Installation (important for CTF)
  result.tests.sshInstall = await testSSHInstallation(
    osConfig.image,
    containerName,
    osConfig.packageManager
  );
  
  // Overall assessment
  const criticalTests = [
    result.tests.pull.success,
    result.tests.containerStart.success
  ];
  
  const optionalTests = [
    result.tests.portConfig.success,
    result.tests.serviceInstall.success,
    result.tests.sshInstall.success
  ];
  
  if (criticalTests.every(t => t)) {
    result.overall = optionalTests.every(t => t) ? 'EXCELLENT' : 'GOOD';
  } else {
    result.overall = 'FAILED';
  }
  
  return result;
}

/**
 * Generate report
 */
async function generateReport(results) {
  const report = {
    timestamp: new Date().toISOString(),
    totalTested: results.length,
    summary: {
      excellent: results.filter(r => r.overall === 'EXCELLENT').length,
      good: results.filter(r => r.overall === 'GOOD').length,
      failed: results.filter(r => r.overall === 'FAILED').length
    },
    results: results
  };
  
  const reportPath = path.join(process.cwd(), 'os-images-test-report.json');
  await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
  
  console.log(`\n${'='.repeat(60)}`);
  console.log('📊 TEST SUMMARY');
  console.log(`${'='.repeat(60)}`);
  console.log(`Total Images Tested: ${results.length}`);
  console.log(`✅ Excellent: ${report.summary.excellent}`);
  console.log(`⚠️  Good: ${report.summary.good}`);
  console.log(`❌ Failed: ${report.summary.failed}`);
  console.log(`\n📄 Full report saved to: ${reportPath}`);
  
  // Print detailed results
  console.log(`\n${'='.repeat(60)}`);
  console.log('📋 DETAILED RESULTS');
  console.log(`${'='.repeat(60)}`);
  
  for (const result of results) {
    console.log(`\n${result.name} (${result.image})`);
    console.log(`  Status: ${result.overall}`);
    console.log(`  Package Manager: ${result.packageManager}`);
    console.log(`  Pull: ${result.tests.pull.success ? '✅' : '❌'}`);
    console.log(`  Container Start: ${result.tests.containerStart.success ? '✅' : '❌'}`);
    console.log(`  Port Config: ${result.tests.portConfig.success ? '✅' : '❌'}`);
    console.log(`  Service Install: ${result.tests.serviceInstall.success ? '✅' : '❌'}`);
    console.log(`  SSH Install: ${result.tests.sshInstall.success ? '✅' : '❌'}`);
    if (result.reason) {
      console.log(`  Reason: ${result.reason}`);
    }
  }
  
  // Recommendations
  console.log(`\n${'='.repeat(60)}`);
  console.log('💡 RECOMMENDATIONS FOR CTF CHALLENGES');
  console.log(`${'='.repeat(60)}`);
  
  const recommended = results.filter(r => 
    r.overall === 'EXCELLENT' || 
    (r.overall === 'GOOD' && r.tests.sshInstall.success)
  );
  
  console.log('\n✅ Recommended Images for Multi-OS Nmap Practice:');
  for (const img of recommended) {
    console.log(`   - ${img.name} (${img.image})`);
    console.log(`     Package Manager: ${img.packageManager}`);
    console.log(`     Size: ${(img.tests.pull.size / 1024 / 1024).toFixed(2)} MB`);
  }
}

/**
 * Main execution
 */
async function main() {
  console.log('🚀 Starting OS Image Testing for CTF Challenges');
  console.log(`Testing ${OS_IMAGES.length} images...`);
  
  for (const osConfig of OS_IMAGES) {
    try {
      const result = await testOSImage(osConfig);
      TEST_RESULTS.push(result);
    } catch (error) {
      console.error(`❌ Error testing ${osConfig.name}: ${error.message}`);
      TEST_RESULTS.push({
        name: osConfig.name,
        image: osConfig.image,
        overall: 'FAILED',
        error: error.message
      });
    }
  }
  
  await generateReport(TEST_RESULTS);
}

// Run if executed directly
const isMainModule = import.meta.url === `file://${path.resolve(process.argv[1])}` || 
                     process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'));

if (isMainModule || process.argv[1]?.includes('test-os-images.js')) {
  main().catch(console.error);
}

export { testOSImage, OS_IMAGES };

