const EventEmitter = require('events');
const { logger } = require('./logger');

class WorkspaceEventEmitter extends EventEmitter {
  constructor() {
    super();
    this.clients = new Map(); // userId -> Set of response objects
  }

  /**
   * Subscribe a client to workspace events for a specific user
   * @param {string} userId - User ID to subscribe to
   * @param {Response} res - Express response object
   */
  subscribe(userId, res) {
    if (!this.clients.has(userId)) {
      this.clients.set(userId, new Set());
    }
    
    this.clients.get(userId).add(res);
    
    logger.info({ userId, clientCount: this.clients.get(userId).size }, 'SSE client subscribed');
    
    // Clean up on connection close
    res.on('close', () => {
      this.unsubscribe(userId, res);
    });
  }

  /**
   * Unsubscribe a client from workspace events
   * @param {string} userId - User ID
   * @param {Response} res - Express response object
   */
  unsubscribe(userId, res) {
    if (this.clients.has(userId)) {
      this.clients.get(userId).delete(res);
      
      if (this.clients.get(userId).size === 0) {
        this.clients.delete(userId);
      }
      
      logger.info({ userId }, 'SSE client unsubscribed');
    }
  }

  /**
   * Publish a workspace update to all subscribed clients for a user
   * @param {string} userId - User ID
   * @param {Object} workspace - Workspace data
   * @param {string} eventType - Event type (created, updated, deleted)
   */
  publish(userId, workspace, eventType = 'updated') {
    if (!this.clients.has(userId)) {
      return;
    }

    const data = {
      type: eventType,
      workspace: workspace,
      timestamp: new Date().toISOString()
    };

    const message = `data: ${JSON.stringify(data)}\n\n`;
    
    const clients = this.clients.get(userId);
    const deadClients = new Set();
    
    clients.forEach(res => {
      try {
        res.write(message);
      } catch (error) {
        logger.warn({ userId, error: error.message }, 'Failed to send SSE message, marking client as dead');
        deadClients.add(res);
      }
    });
    
    // Clean up dead clients
    deadClients.forEach(res => {
      clients.delete(res);
    });
    
    logger.debug({ userId, eventType, workspaceId: workspace.id, clientCount: clients.size }, 'SSE event published');
  }

  /**
   * Send a heartbeat to all connected clients
   */
  heartbeat() {
    this.clients.forEach((clients, userId) => {
      const deadClients = new Set();
      
      clients.forEach(res => {
        try {
          res.write(': heartbeat\n\n');
        } catch (error) {
          deadClients.add(res);
        }
      });
      
      deadClients.forEach(res => {
        clients.delete(res);
      });
      
      if (clients.size === 0) {
        this.clients.delete(userId);
      }
    });
  }
}

// Singleton instance
const workspaceEvents = new WorkspaceEventEmitter();

// Send heartbeat every 30 seconds to keep connections alive
setInterval(() => {
  workspaceEvents.heartbeat();
}, 30000);

module.exports = workspaceEvents;
