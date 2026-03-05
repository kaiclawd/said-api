import { WebSocketServer, WebSocket } from 'ws';
import type { Server } from 'http';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { PrismaClient } from '@prisma/client';
import { wsClients, getWsKey } from './ws-clients.js';
import { resolveAgent } from './cross-chain-resolver.js';
import { getFreeTierInfo, hasFreeTierRemaining, consumeFreeTier, MESSAGE_PRICE } from './x402-config.js';
import { deliverToWebhook } from './cross-chain-endpoints.js';

const prisma = new PrismaClient();

const SAID_TREASURY = process.env.SAID_X402_TREASURY || 'EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas';

interface AuthedClient {
  ws: WebSocket;
  wallet: string;
  chain: string;
  key: string;
  lastPong: number;
}

const authedClients = new Map<WebSocket, AuthedClient>();

function verifyWsAuth(wallet: string, signature: string, timestamp: number): boolean {
  try {
    const message = `SAID:ws:${wallet}:${timestamp}`;
    const messageBytes = new TextEncoder().encode(message);
    const sigBytes = bs58.decode(signature);
    const pubkeyBytes = bs58.decode(wallet);
    if (Math.abs(Date.now() - timestamp) > 5 * 60 * 1000) return false;
    return nacl.sign.detached.verify(messageBytes, sigBytes, pubkeyBytes);
  } catch {
    return false;
  }
}

function send(ws: WebSocket, data: Record<string, unknown>) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(data));
  }
}

export function setupWebSocket(server: Server) {
  const wss = new WebSocketServer({ server, path: '/ws' });

  // Heartbeat: ping every 30s, disconnect after 90s no pong
  const pingInterval = setInterval(() => {
    const now = Date.now();
    for (const [ws, client] of authedClients) {
      if (now - client.lastPong > 90_000) {
        console.log(`[WS] Disconnecting ${client.wallet} (no pong for 90s)`);
        ws.terminate();
        continue;
      }
      send(ws, { type: 'ping' });
    }
  }, 30_000);

  wss.on('close', () => clearInterval(pingInterval));

  wss.on('connection', (ws) => {
    // Auth timeout: must auth within 30s
    const authTimeout = setTimeout(() => {
      if (!authedClients.has(ws)) {
        send(ws, { type: 'error', error: 'Auth timeout' });
        ws.close();
      }
    }, 30_000);

    ws.on('message', async (raw) => {
      let msg: any;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        send(ws, { type: 'error', error: 'Invalid JSON' });
        return;
      }

      // Handle pong
      if (msg.type === 'pong') {
        const client = authedClients.get(ws);
        if (client) client.lastPong = Date.now();
        return;
      }

      // Handle auth
      if (msg.type === 'auth') {
        clearTimeout(authTimeout);
        const { wallet, chain, signature, timestamp } = msg;

        if (!wallet || !signature || !timestamp) {
          send(ws, { type: 'auth_error', error: 'Missing fields: wallet, signature, timestamp' });
          ws.close();
          return;
        }

        const authChain = chain || 'solana';

        if (authChain !== 'solana') {
          send(ws, { type: 'auth_error', error: 'Only solana auth supported currently' });
          ws.close();
          return;
        }

        if (!verifyWsAuth(wallet, signature, timestamp)) {
          send(ws, { type: 'auth_error', error: 'Invalid signature or expired timestamp' });
          ws.close();
          return;
        }

        const key = getWsKey(authChain, wallet);

        // Disconnect existing connection for same wallet
        const existing = wsClients.get(key);
        if (existing && existing !== ws) {
          send(existing as any, { type: 'error', error: 'Replaced by new connection' });
          (existing as any).close();
        }

        wsClients.set(key, ws as any);
        authedClients.set(ws, { ws, wallet, chain: authChain, key, lastPong: Date.now() });

        send(ws, { type: 'auth_ok', wallet, chain: authChain });
        console.log(`[WS] Authenticated: ${wallet} (${authChain})`);
        return;
      }

      // All other messages require auth
      const client = authedClients.get(ws);
      if (!client) {
        send(ws, { type: 'error', error: 'Not authenticated' });
        return;
      }

      // Handle send
      if (msg.type === 'send') {
        const { to, message } = msg;
        if (!to?.address || !to?.chain || !message) {
          send(ws, { type: 'send_error', error: 'Missing fields: to.address, to.chain, message' });
          return;
        }

        try {
          // Check free tier
          if (!hasFreeTierRemaining(client.wallet)) {
            send(ws, {
              type: 'payment_required',
              price: MESSAGE_PRICE,
              payTo: SAID_TREASURY,
              network: 'solana',
            });
            return;
          }

          // Resolve agents
          const [senderResults, recipientResults] = await Promise.all([
            resolveAgent(client.wallet, client.chain),
            resolveAgent(to.address, to.chain),
          ]);

          if (senderResults.length === 0) {
            send(ws, { type: 'send_error', error: 'Sender not registered' });
            return;
          }
          if (recipientResults.length === 0) {
            send(ws, { type: 'send_error', error: 'Recipient not found' });
            return;
          }

          const sender = senderResults[0];
          const recipient = recipientResults[0];
          const messageId = `xmsg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

          // Store message
          await prisma.a2AMessage.create({
            data: {
              fromWallet: `${client.chain}:${client.wallet}`,
              toWallet: `${to.chain}:${to.address}`,
              message,
              context: JSON.stringify({
                crossChain: true,
                fromChain: client.chain,
                toChain: to.chain,
                fromSource: sender.source,
                toSource: recipient.source,
                fromName: sender.name,
                toName: recipient.name,
                viaWs: true,
              }),
              taskId: messageId,
              fromVerified: sender.verified,
              status: 'created',
              progress: 0,
            },
          });

          // Consume free tier
          consumeFreeTier(client.wallet);

          // Push to recipient if connected via WS
          const recipientKey = getWsKey(to.chain, to.address);
          const recipientWs = wsClients.get(recipientKey);
          let delivered = false;

          if (recipientWs && (recipientWs as any).readyState === WebSocket.OPEN) {
            send(recipientWs as any, {
              type: 'message',
              messageId,
              from: {
                address: client.wallet,
                chain: client.chain,
                name: sender.name,
              },
              message,
              createdAt: new Date().toISOString(),
            });
            delivered = true;
          }

          // Also try A2A + webhook delivery
          const deliveryPayload = {
            from: {
              address: client.wallet,
              chain: client.chain,
              name: sender.name,
              verified: sender.verified,
              reputation: sender.reputationScore,
              source: sender.source,
            },
            message,
            messageId,
            protocol: 'said-xchain-v1',
            timestamp: new Date().toISOString(),
          };

          if (recipient.endpoint) {
            try {
              const res = await fetch(recipient.endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(deliveryPayload),
                signal: AbortSignal.timeout(10000),
              });
              if (res.ok) delivered = true;
            } catch {}
          }

          const webhookDelivered = await deliverToWebhook(to.chain, to.address, deliveryPayload);
          if (webhookDelivered) delivered = true;

          if (delivered) {
            await prisma.a2AMessage.update({
              where: { taskId: messageId },
              data: { status: 'routed' },
            });
          }

          send(ws, { type: 'send_ok', messageId, paid: false });
        } catch (err: any) {
          console.error('[WS Send Error]', err.message);
          send(ws, { type: 'send_error', error: 'Internal error' });
        }
        return;
      }

      // Unknown message type
      send(ws, { type: 'error', error: `Unknown message type: ${msg.type}` });
    });

    ws.on('close', () => {
      clearTimeout(authTimeout);
      const client = authedClients.get(ws);
      if (client) {
        wsClients.delete(client.key);
        authedClients.delete(ws);
        console.log(`[WS] Disconnected: ${client.wallet}`);
      }
    });

    ws.on('error', (err) => {
      console.error('[WS Error]', err.message);
    });
  });

  console.log('✅ WebSocket server attached at /ws');
  return wss;
}
