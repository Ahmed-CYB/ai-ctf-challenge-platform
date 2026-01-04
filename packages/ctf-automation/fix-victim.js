/**
 * Quick Victim Container Diagnostic & Repair Tool
 */

import { execSync } from 'child_process';

const challengeName = process.argv[2] || 'ftp-smb-eternalblue-exploit';

console.log(`\n🔍 Diagnosing victim container for: ${challengeName}\n`);
console.log('='.repeat(60));

try {
  // 1. Check if victim container exists and is running
  console.log('\n📦 Container Status:');
  try {
    const containerStatus = execSync(
      `docker ps -a --filter "name=ctf-${challengeName}-victim" --format "{{.Names}}|{{.Status}}|{{.Ports}}"`,
      { encoding: 'utf-8' }
    ).trim();

    if (!containerStatus) {
      console.log('❌ Victim container not found!');
      process.exit(1);
    }

    const [name, status, ports] = containerStatus.split('|');
    console.log(`   Name: ${name}`);
    console.log(`   Status: ${status}`);
    console.log(`   Ports: ${ports || 'None'}`);

    if (!status.includes('Up')) {
      console.log('\n❌ Container is not running!');
      console.log('\n🔧 Attempting to start container...');
      
      try {
        execSync(`docker start ctf-${challengeName}-victim`, { encoding: 'utf-8' });
        console.log('✅ Container started');
      } catch (startError) {
        console.log('❌ Failed to start container');
        console.log('\n📋 Container logs:');
        const logs = execSync(`docker logs --tail 50 ctf-${challengeName}-victim`, { encoding: 'utf-8' });
        console.log(logs);
      }
    }
  } catch (error) {
    console.log('❌ Error checking container:', error.message);
  }

  // 2. Check container logs for errors
  console.log('\n📋 Recent Container Logs:');
  try {
    const logs = execSync(`docker logs --tail 30 ctf-${challengeName}-victim`, { encoding: 'utf-8' });
    console.log(logs || '   (No logs)');
  } catch (error) {
    console.log('❌ Error reading logs:', error.message);
  }

  // 3. Check if services are running inside container
  console.log('\n🔌 Service Status:');
  
  // Check FTP
  try {
    const vsftpdStatus = execSync(
      `docker exec ctf-${challengeName}-victim bash -c "ps aux | grep vsftpd | grep -v grep"`,
      { encoding: 'utf-8' }
    ).trim();
    
    if (vsftpdStatus) {
      console.log('   ✅ vsftpd: Running');
    } else {
      console.log('   ❌ vsftpd: Not running');
    }
  } catch (error) {
    console.log('   ❌ vsftpd: Not running');
  }

  // Check SMB
  try {
    const smbdStatus = execSync(
      `docker exec ctf-${challengeName}-victim bash -c "ps aux | grep smbd | grep -v grep"`,
      { encoding: 'utf-8' }
    ).trim();
    
    if (smbdStatus) {
      console.log('   ✅ smbd: Running');
    } else {
      console.log('   ❌ smbd: Not running');
    }
  } catch (error) {
    console.log('   ❌ smbd: Not running');
  }

  // 4. Check listening ports
  console.log('\n🔊 Listening Ports:');
  try {
    const ports = execSync(
      `docker exec ctf-${challengeName}-victim netstat -tlnp 2>/dev/null | grep LISTEN`,
      { encoding: 'utf-8' }
    );
    console.log(ports || '   (No listening ports found)');
  } catch (error) {
    console.log('   ❌ Error checking ports');
  }

  // 5. Check flag files
  console.log('\n🚩 Flag Files:');
  try {
    const ftpFlag = execSync(
      `docker exec ctf-${challengeName}-victim bash -c "[ -f /srv/ftp/flag.txt ] && cat /srv/ftp/flag.txt || echo 'NOT FOUND'"`,
      { encoding: 'utf-8' }
    ).trim();
    console.log(`   FTP Flag: ${ftpFlag}`);
  } catch (error) {
    console.log('   FTP Flag: ERROR');
  }

  try {
    const smbFlag = execSync(
      `docker exec ctf-${challengeName}-victim bash -c "[ -f /srv/samba/share/flag.txt ] && cat /srv/samba/share/flag.txt || echo 'NOT FOUND'"`,
      { encoding: 'utf-8' }
    ).trim();
    console.log(`   SMB Flag: ${smbFlag}`);
  } catch (error) {
    console.log('   SMB Flag: ERROR');
  }

  // 6. Quick Fixes
  console.log('\n🔧 Applying Quick Fixes:');
  
  // Fix 1: Create vsftpd directory
  try {
    execSync(
      `docker exec ctf-${challengeName}-victim mkdir -p /var/run/vsftpd/empty`,
      { encoding: 'utf-8' }
    );
    console.log('   ✅ Created /var/run/vsftpd/empty');
  } catch (error) {
    console.log('   ⚠️ Could not create vsftpd directory');
  }

  // Fix 2: Restart services
  console.log('\n🔄 Restarting Services:');
  
  // Restart FTP
  try {
    execSync(
      `docker exec ctf-${challengeName}-victim bash -c "service vsftpd restart 2>&1"`,
      { encoding: 'utf-8' }
    );
    console.log('   ✅ FTP service restarted');
  } catch (error) {
    console.log('   ❌ FTP restart failed:', error.stderr?.toString().substring(0, 200) || error.message.substring(0, 200));
  }

  // Restart SMB
  try {
    execSync(
      `docker exec ctf-${challengeName}-victim bash -c "service smbd restart 2>&1"`,
      { encoding: 'utf-8' }
    );
    console.log('   ✅ SMB service restarted');
  } catch (error) {
    console.log('   ❌ SMB restart failed:', error.stderr?.toString().substring(0, 200) || error.message.substring(0, 200));
  }

  // 7. Test services from attacker
  console.log('\n🧪 Testing Services:');
  
  try {
    const victimIP = execSync(
      `docker exec ctf-${challengeName}-victim hostname -I`,
      { encoding: 'utf-8' }
    ).trim().split(' ')[0];
    
    console.log(`   Victim IP: ${victimIP}`);

    // Test FTP
    try {
      const ftpTest = execSync(
        `docker exec ctf-${challengeName}-attacker timeout 3 nc -zv ${victimIP} 21 2>&1`,
        { encoding: 'utf-8' }
      );
      if (ftpTest.includes('open') || ftpTest.includes('succeeded')) {
        console.log('   ✅ FTP port 21 is accessible');
      } else {
        console.log('   ❌ FTP port 21 not accessible');
      }
    } catch (error) {
      const output = error.stderr?.toString() || error.stdout?.toString() || '';
      if (output.includes('open') || output.includes('succeeded')) {
        console.log('   ✅ FTP port 21 is accessible');
      } else {
        console.log('   ❌ FTP port 21 not accessible');
      }
    }

    // Test SMB
    try {
      const smbTest = execSync(
        `docker exec ctf-${challengeName}-attacker timeout 3 nc -zv ${victimIP} 445 2>&1`,
        { encoding: 'utf-8' }
      );
      if (smbTest.includes('open') || smbTest.includes('succeeded')) {
        console.log('   ✅ SMB port 445 is accessible');
      } else {
        console.log('   ❌ SMB port 445 not accessible');
      }
    } catch (error) {
      const output = error.stderr?.toString() || error.stdout?.toString() || '';
      if (output.includes('open') || output.includes('succeeded')) {
        console.log('   ✅ SMB port 445 is accessible');
      } else {
        console.log('   ❌ SMB port 445 not accessible');
      }
    }

  } catch (error) {
    console.log('   ❌ Error testing services');
  }

  console.log('\n' + '='.repeat(60));
  console.log('\n💡 Summary:');
  console.log('   If services are still not working, the challenge may need to be rebuilt.');
  console.log('   Common issues:');
  console.log('   - vsftpd needs /var/run/vsftpd/empty directory (now created)');
  console.log('   - Services may need manual startup scripts');
  console.log('   - SMB password setup may have failed during build');
  console.log('\n🔧 Manual Fix Command:');
  console.log(`   docker exec -it ctf-${challengeName}-victim bash`);
  console.log('   Then manually start services with:');
  console.log('   - service vsftpd start');
  console.log('   - service smbd start');

} catch (error) {
  console.error('\n❌ Fatal error:', error.message);
  process.exit(1);
}
