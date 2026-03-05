import type WebSocket from 'ws';

// key: "chain:address" (address lowercased)
export const wsClients = new Map<string, WebSocket>();

export function getWsKey(chain: string, address: string): string {
  return `${chain}:${address.toLowerCase()}`;
}
