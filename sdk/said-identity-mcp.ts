/**
 * SAID Identity MCP server — exposes agent identity + reputation as MCP tools
 * so any MCP-native agent framework (Claude, OpenClaw, Cursor, primitive,
 * AgentPhone, Clawvisor, …) can verify who it's dealing with and gate on trust.
 *
 * Reference integration. To run:
 *   npm i @modelcontextprotocol/sdk
 *   tsx said-identity-mcp.ts
 *
 * Then add to an mcpServers config alongside the agent's other tools.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { SaidIdentity } from './said-identity.js';

const said = new SaidIdentity({ baseUrl: process.env.SAID_API_URL });

const server = new McpServer({ name: 'said-identity', version: '0.1.0' });

server.tool(
  'said_lookup_identity',
  "Look up an AI agent's SAID identity and reputation by its id (or wallet/pda). " +
    'Returns name, verification status, reputation score (0-100), tier, and capabilities. ' +
    'Use this to know who an agent is before trusting or transacting with it.',
  { id: z.string().describe('SAID agent id (cuid), or a wallet / pda address') },
  async ({ id }) => {
    const agent = await said.get(id);
    if (!agent) {
      return { content: [{ type: 'text', text: `No SAID identity found for "${id}".` }] };
    }
    return { content: [{ type: 'text', text: JSON.stringify(agent, null, 2) }] };
  },
);

server.tool(
  'said_check_reputation',
  'Check whether an AI agent meets a minimum reputation bar. Returns allow/deny ' +
    'plus the score. Use this to reputation-gate access — e.g. only accept messages, ' +
    'calls, or payments from agents at or above a threshold.',
  {
    id: z.string().describe('SAID agent id (cuid), or a wallet / pda address'),
    min: z.number().min(0).max(100).describe('Minimum reputation score, 0-100'),
  },
  async ({ id, min }) => {
    const agent = await said.get(id);
    const allow = !!agent && agent.verified && agent.reputation.score >= min;
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              allow,
              score: agent?.reputation.score ?? null,
              tier: agent?.reputation.tier ?? null,
              verified: agent?.verified ?? false,
              reason: !agent
                ? 'not_found'
                : !agent.verified
                  ? 'unverified'
                  : agent.reputation.score >= min
                    ? 'meets_threshold'
                    : 'below_threshold',
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
