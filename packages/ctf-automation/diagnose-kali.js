// Kali Container Diagnostic Tool
// Run this to check Kali container status and accessibility

import Docker from 'dockerode';

const docker = new Docker();

async function diagnoseKaliContainer() {
  console.log('\n🔍 Kali Linux Container Diagnostics\n');
  console.log('=' .repeat(60));

  try {
    // Find Kali containers
    const containers = await docker.listContainers({ all: true });
    const kaliContainers = containers.filter(c => 
      c.Image.includes('kali') || c.Names.some(n => n.includes('attacker'))
    );

    if (kaliContainers.length === 0) {
      console.log('❌ No Kali containers found');
      return;
    }

    for (const containerInfo of kaliContainers) {
      const container = docker.getContainer(containerInfo.Id);
      const inspect = await container.inspect();
      
      console.log(`\n📦 Container: ${containerInfo.Names[0]}`);
      console.log(`   ID: ${containerInfo.Id.substring(0, 12)}`);
      console.log(`   Image: ${containerInfo.Image}`);
      console.log(`   Status: ${containerInfo.Status}`);
      console.log(`   State: ${containerInfo.State}`);
      
      // Check if running
      if (inspect.State.Running) {
        console.log('   ✅ Container is RUNNING');
        
        // Check uptime
        const startedAt = new Date(inspect.State.StartedAt);
        const uptime = Math.floor((Date.now() - startedAt.getTime()) / 1000);
        console.log(`   ⏱️  Uptime: ${uptime} seconds`);
        
        // Check network
        const networks = Object.keys(inspect.NetworkSettings.Networks);
        console.log(`   🌐 Networks: ${networks.join(', ')}`);
        
        for (const netName of networks) {
          const net = inspect.NetworkSettings.Networks[netName];
          console.log(`      - ${netName}: ${net.IPAddress}`);
        }
        
        // Check ports
        console.log('   🔌 Port Bindings:');
        const ports = inspect.NetworkSettings.Ports || {};
        
        if (Object.keys(ports).length === 0) {
          console.log('      ❌ No ports bound!');
        } else {
          for (const [containerPort, bindings] of Object.entries(ports)) {
            if (bindings && bindings.length > 0) {
              for (const binding of bindings) {
                const hostIp = binding.HostIp || '0.0.0.0';
                const hostPort = binding.HostPort;
                console.log(`      ✅ ${containerPort} -> ${hostIp}:${hostPort}`);
                
                // Try to connect
                if (containerPort === '6901/tcp') {
                  console.log(`      🌍 Access URL: http://localhost:${hostPort}`);
                  console.log(`      🌍 Alt URL: http://127.0.0.1:${hostPort}`);
                }
              }
            } else {
              console.log(`      ⚠️  ${containerPort} - No host binding`);
            }
          }
        }
        
        // Check environment variables
        console.log('   🔐 Environment:');
        const envVars = inspect.Config.Env || [];
        const relevantEnv = envVars.filter(e => 
          e.startsWith('VNC_') || 
          e.startsWith('KASM_') || 
          e.includes('PASSWORD') ||
          e.includes('PORT')
        );
        
        if (relevantEnv.length > 0) {
          relevantEnv.forEach(env => {
            console.log(`      ${env}`);
          });
        } else {
          console.log('      ⚠️  No VNC/KASM environment variables found');
        }
        
        // Check resource limits
        console.log('   💾 Resources:');
        console.log(`      ShmSize: ${inspect.HostConfig.ShmSize ? (inspect.HostConfig.ShmSize / 1024 / 1024).toFixed(0) + 'MB' : 'default'}`);
        
        // Try to get logs
        console.log('\n   📋 Recent Logs (last 10 lines):');
        try {
          const logs = await container.logs({
            stdout: true,
            stderr: true,
            tail: 10
          });
          
          const logText = logs.toString('utf8');
          if (logText.trim()) {
            console.log('   ' + '-'.repeat(58));
            logText.split('\n').slice(0, 10).forEach(line => {
              if (line.trim()) {
                console.log(`   ${line.substring(0, 100)}`);
              }
            });
            console.log('   ' + '-'.repeat(58));
          } else {
            console.log('      (No logs available)');
          }
        } catch (error) {
          console.log('      ⚠️  Could not retrieve logs');
        }
        
      } else {
        console.log(`   ❌ Container is NOT running: ${inspect.State.Status}`);
        if (inspect.State.Error) {
          console.log(`   Error: ${inspect.State.Error}`);
        }
      }
    }
    
    console.log('\n' + '='.repeat(60));
    console.log('\n💡 Troubleshooting Tips:');
    console.log('   1. Check if port is accessible: curl http://localhost:<port>');
    console.log('   2. Check Windows Firewall settings');
    console.log('   3. Ensure Docker Desktop is running');
    console.log('   4. Wait 10-15 seconds after container starts for VNC to initialize');
    console.log('   5. Check Docker Desktop logs for the container');
    console.log('   6. Try accessing with browser: http://localhost:<port>');
    console.log('   7. Default credentials: kasm_user / password');
    console.log('\n');
    
  } catch (error) {
    console.error('❌ Error during diagnosis:', error.message);
  }
}

// Run diagnostics
diagnoseKaliContainer().catch(console.error);
