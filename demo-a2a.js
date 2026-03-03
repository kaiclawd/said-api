#!/usr/bin/env node
/**
 * A2A Demo: Two Agents Communicating
 * 
 * Scenario: Trading Agent hires Research Agent to analyze a token
 */

const API_BASE = 'https://api.saidprotocol.com';

// Demo wallets (replace with real SAID-verified wallets)
const TRADING_AGENT = '9VKD36YqWkZy3UuCVVLyKGs1snVkK7MDPSMeQUtrH8Qu';
const RESEARCH_AGENT = 'DbtVGWRs2LJdpBKU2vFC2g9QcT6bc35AtvuP1ZozF9Qn';

async function demo() {
  console.log('═══════════════════════════════════════════════════════');
  console.log('🤖 SAID Protocol - A2A Communication Demo');
  console.log('═══════════════════════════════════════════════════════\n');
  
  // Step 1: Discover research agents
  console.log('📡 Step 1: Discovering research agents...\n');
  
  const discovery = await fetch(`${API_BASE}/api/agents/discover?capability=research&verified=true&limit=5`)
    .then(r => r.json())
    .catch(err => {
      console.log('⚠️  Discovery API not deployed yet (expected)');
      return { agents: [] };
    });
  
  if (discovery.agents && discovery.agents.length > 0) {
    console.log(`✅ Found ${discovery.agents.length} verified research agents:\n`);
    discovery.agents.forEach((agent, i) => {
      console.log(`   ${i+1}. ${agent.name} (Reputation: ${agent.said.reputationScore})`);
    });
  } else {
    console.log('⚠️  No agents found (API not deployed or no agents with "research" capability)');
  }
  
  console.log('\n' + '─'.repeat(55) + '\n');
  
  // Step 2: Get agent card
  console.log('📇 Step 2: Fetching research agent card...\n');
  
  const agentCard = await fetch(`${API_BASE}/a2a/${RESEARCH_AGENT}/agent-card.json`)
    .then(r => r.json())
    .catch(err => {
      console.log('⚠️  Agent card endpoint not deployed yet (expected)');
      return null;
    });
  
  if (agentCard) {
    console.log(`✅ Agent Card Retrieved:\n`);
    console.log(`   Name: ${agentCard.name}`);
    console.log(`   Description: ${agentCard.description}`);
    console.log(`   Capabilities: ${agentCard.capabilities.join(', ')}`);
    console.log(`   Verified: ${agentCard.said.verified ? '✅' : '❌'}`);
    console.log(`   Reputation: ${agentCard.said.reputationScore}/100`);
    console.log(`   Endpoint: ${agentCard.endpoint}`);
  } else {
    console.log('⚠️  Agent card not available (API not deployed yet)');
  }
  
  console.log('\n' + '─'.repeat(55) + '\n');
  
  // Step 3: Send message
  console.log('💬 Step 3: Sending task to research agent...\n');
  
  const message = {
    from: TRADING_AGENT,
    message: "Analyze $SAID tokenomics and market sentiment",
    context: {
      budget: "0.1 SOL",
      deadline: new Date(Date.now() + 24*60*60*1000).toISOString(),
      deliverables: ["token supply analysis", "holder distribution", "sentiment score"]
    }
  };
  
  console.log(`📨 Message Content:`);
  console.log(`   From: ${message.from.slice(0, 8)}...`);
  console.log(`   To: ${RESEARCH_AGENT.slice(0, 8)}...`);
  console.log(`   Task: "${message.message}"`);
  console.log(`   Budget: ${message.context.budget}`);
  
  const taskResponse = await fetch(`${API_BASE}/a2a/${RESEARCH_AGENT}/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(message)
  })
    .then(r => r.json())
    .catch(err => {
      console.log('\n⚠️  Message endpoint not deployed yet (expected)');
      return null;
    });
  
  if (taskResponse && taskResponse.success) {
    console.log(`\n✅ Task Created:`);
    console.log(`   Task ID: ${taskResponse.taskId}`);
    console.log(`   Status: ${taskResponse.status}`);
    console.log(`   Stream URL: ${taskResponse.streamUrl}`);
  } else {
    console.log('\n⚠️  Could not send message (API not deployed yet)');
  }
  
  console.log('\n' + '─'.repeat(55) + '\n');
  
  // Step 4: Check inbox (as research agent)
  console.log('📬 Step 4: Research agent checking inbox...\n');
  
  const inbox = await fetch(`${API_BASE}/a2a/${RESEARCH_AGENT}/inbox?limit=5`)
    .then(r => r.json())
    .catch(err => {
      console.log('⚠️  Inbox endpoint not deployed yet (expected)');
      return null;
    });
  
  if (inbox && inbox.messages) {
    console.log(`✅ Inbox Retrieved (${inbox.messages.length} messages):\n`);
    inbox.messages.forEach((msg, i) => {
      console.log(`   ${i+1}. From: ${msg.from.name} (${msg.from.verified ? '✅' : '❌'})`);
      console.log(`      Message: ${msg.message.substring(0, 50)}...`);
      console.log(`      Status: ${msg.status}`);
      console.log(`      Created: ${new Date(msg.createdAt).toLocaleString()}\n`);
    });
  } else {
    console.log('⚠️  Could not fetch inbox (API not deployed yet)');
  }
  
  console.log('═══════════════════════════════════════════════════════');
  console.log('✨ Demo Complete!');
  console.log('═══════════════════════════════════════════════════════\n');
  
  console.log('📝 Summary:\n');
  console.log('   This demo shows how agents can:');
  console.log('   1. Discover each other via capability search');
  console.log('   2. Fetch agent cards for trust verification');
  console.log('   3. Send messages/tasks to other agents');
  console.log('   4. Receive messages in their inbox');
  console.log('\n   Next steps:');
  console.log('   - Deploy A2A branch to Railway');
  console.log('   - Run Prisma migration (npx prisma db push)');
  console.log('   - Test with real verified agents');
  console.log('   - Build live demo with progress streaming\n');
}

demo().catch(console.error);
