/**
 * Tool Learning CLI
 * Test and manage the tool learning system
 */

import { learnToolInstallation, getToolStats, learnMultipleTools } from './tool-learning-service.js';
import { query } from './db-manager.js';

const command = process.argv[2];
const args = process.argv.slice(3);

async function main() {
  switch (command) {
    case 'learn':
      if (!args[0]) {
        console.error('Usage: npm run tool-learn learn <tool-name> [category]');
        process.exit(1);
      }
      await learnToolInstallation(args[0], args[1] || 'misc');
      break;

    case 'learn-many':
      if (args.length === 0) {
        console.error('Usage: npm run tool-learn learn-many <tool1> <tool2> <tool3> ...');
        process.exit(1);
      }
      await learnMultipleTools(args);
      break;

    case 'stats':
      const stats = await getToolStats();
      console.log('\n📊 Tool Learning Statistics:');
      console.log('═'.repeat(50));
      console.log(`Total tools attempted: ${stats.total_tools_attempted}`);
      console.log(`Successful tools: ${stats.successful_tools}`);
      console.log(`Total successes: ${stats.total_successes}`);
      console.log(`Total failures: ${stats.total_failures}`);
      console.log(`Average success time: ${Math.round(stats.avg_success_time)}ms`);
      console.log(`\nLearning Queue:`);
      console.log(`  ✅ Learned: ${stats.tools_learned}`);
      console.log(`  ❌ Failed: ${stats.tools_failed}`);
      console.log(`  ⏳ Pending: ${stats.tools_pending}`);
      break;

    case 'list':
      const tools = await query(`
        SELECT t.tool_name, t.category, tim.method, tim.package_name, tim.success_count, tim.last_successful_at
        FROM ctf_tools t
        JOIN tool_installation_methods tim ON t.id = tim.tool_id
        ORDER BY t.category, t.tool_name
      `);
      
      console.log('\n📚 Learned Tools:');
      console.log('═'.repeat(80));
      
      let currentCategory = '';
      for (const tool of tools.rows) {
        if (tool.category !== currentCategory) {
          console.log(`\n${tool.category.toUpperCase()}:`);
          currentCategory = tool.category;
        }
        console.log(`  ${tool.tool_name.padEnd(30)} ${tool.method.padEnd(8)} ${tool.package_name.padEnd(30)} ✓${tool.success_count}`);
      }
      break;

    case 'logs':
      const limit = args[0] || 20;
      const logs = await query(`
        SELECT tool_name, method, success, error_message, execution_time_ms, attempted_at
        FROM tool_installation_logs
        ORDER BY attempted_at DESC
        LIMIT $1
      `, [limit]);

      console.log(`\n📜 Recent Installation Attempts (last ${limit}):`);
      console.log('═'.repeat(100));
      
      for (const log of logs.rows) {
        const status = log.success ? '✅' : '❌';
        const time = new Date(log.attempted_at).toLocaleString();
        const duration = `${log.execution_time_ms}ms`;
        console.log(`${status} ${log.tool_name.padEnd(25)} ${log.method.padEnd(8)} ${duration.padEnd(10)} ${time}`);
        if (!log.success && log.error_message) {
          console.log(`     Error: ${log.error_message.substring(0, 80)}`);
        }
      }
      break;

    case 'queue':
      const queueItems = await query(`
        SELECT tool_name, category, status, attempts, last_error, updated_at
        FROM tool_learning_queue
        ORDER BY 
          CASE status 
            WHEN 'in_progress' THEN 1 
            WHEN 'pending' THEN 2 
            WHEN 'failed' THEN 3 
            WHEN 'learned' THEN 4 
          END,
          updated_at DESC
      `);

      console.log('\n⏳ Learning Queue:');
      console.log('═'.repeat(100));
      
      for (const item of queueItems.rows) {
        const statusIcon = {
          'pending': '⏳',
          'in_progress': '🔄',
          'learned': '✅',
          'failed': '❌'
        }[item.status];
        
        console.log(`${statusIcon} ${item.tool_name.padEnd(25)} ${item.category.padEnd(12)} ${item.status.padEnd(12)} Attempts: ${item.attempts}`);
        if (item.last_error) {
          console.log(`     Last error: ${item.last_error.substring(0, 100)}`);
        }
      }
      break;

    case 'seed-network':
      console.log('🌱 Seeding network tools...');
      const networkTools = [
        'nmap', 'masscan', 'wireshark-common', 'tshark', 
        'tcpdump', 'netcat-traditional', 'hping3', 'arp-scan', 'netdiscover'
      ];
      await learnMultipleTools(networkTools, 'network');
      console.log('✅ Network tools seeded');
      break;

    case 'seed-web':
      console.log('🌱 Seeding web tools...');
      const webTools = [
        'sqlmap', 'nikto', 'gobuster', 'ffuf', 
        'curl', 'wget', 'python3-requests'
      ];
      await learnMultipleTools(webTools, 'web');
      console.log('✅ Web tools seeded');
      break;

    case 'seed-all':
      console.log('🌱 Seeding all common tools...');
      await query(`SELECT setval('ctf_tools_id_seq', 1, false)`); // Reset IDs if fresh start
      
      const allTools = [
        // Base
        'openssh-server', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools', 'iputils-ping',
        // Forensics
        'binwalk', 'foremost', 'sleuthkit', 'steghide', 'file', 'hexedit', 'p7zip-full', 'unrar', 'binutils', 'volatility3',
        // Network
        'nmap', 'masscan', 'tcpdump', 'netcat-traditional', 'hping3', 'arp-scan',
        // Web
        'sqlmap', 'nikto', 'gobuster', 'ffuf',
        // Crypto
        'hashcat', 'john', 'openssl'
      ];
      
      await learnMultipleTools(allTools, 'misc');
      console.log('✅ All tools seeded');
      break;

    case 'help':
    default:
      console.log(`
Tool Learning CLI - Manage the self-learning tool installation system

Usage: node tool-learn-cli.js <command> [args]

Commands:
  learn <tool> [category]    Learn installation method for a single tool
  learn-many <tool1> <tool2> Learn multiple tools
  stats                      Show learning statistics
  list                       List all learned tools
  logs [limit]              Show recent installation attempts (default: 20)
  queue                      Show learning queue status
  seed-network              Seed common network tools
  seed-web                  Seed common web tools
  seed-all                  Seed all common tools
  help                      Show this help message

Examples:
  node tool-learn-cli.js learn nmap network
  node tool-learn-cli.js learn-many sqlmap nikto gobuster
  node tool-learn-cli.js seed-network
  node tool-learn-cli.js stats
`);
  }

  process.exit(0);
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});
