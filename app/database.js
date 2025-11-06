const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data', 'database.db');
let db;

function initialize() {
  db = new Database(DB_PATH);
  
  // Create tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT,
      email TEXT,
      avatar TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS workspaces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      repo_url TEXT NOT NULL,
      container_id TEXT,
      status TEXT DEFAULT 'stopped',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      UNIQUE(user_id, name)
    );

    CREATE INDEX IF NOT EXISTS idx_workspaces_user_id ON workspaces(user_id);
  `);
}

function upsertUser(user) {
  const stmt = db.prepare(`
    INSERT INTO users (id, username, display_name, email, avatar, updated_at)
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
      username = excluded.username,
      display_name = excluded.display_name,
      email = excluded.email,
      avatar = excluded.avatar,
      updated_at = CURRENT_TIMESTAMP
  `);
  
  return stmt.run(user.id, user.username, user.displayName, user.email, user.avatar);
}

function getUserById(id) {
  const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
  return stmt.get(id);
}

function getUserWorkspaces(userId) {
  const stmt = db.prepare('SELECT * FROM workspaces WHERE user_id = ? ORDER BY created_at DESC');
  return stmt.all(userId);
}

function createWorkspace(workspace) {
  const stmt = db.prepare(`
    INSERT INTO workspaces (user_id, name, repo_url, container_id, status)
    VALUES (?, ?, ?, ?, ?)
  `);
  
  const result = stmt.run(
    workspace.userId,
    workspace.name,
    workspace.repoUrl,
    workspace.containerId,
    workspace.status
  );
  
  return result.lastInsertRowid;
}

function getWorkspace(id) {
  const stmt = db.prepare('SELECT * FROM workspaces WHERE id = ?');
  return stmt.get(id);
}

function updateWorkspaceStatus(id, status) {
  const stmt = db.prepare('UPDATE workspaces SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
  return stmt.run(status, id);
}

function updateWorkspaceContainer(id, containerId, status) {
  const stmt = db.prepare('UPDATE workspaces SET container_id = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
  return stmt.run(containerId, status, id);
}

function getWorkspaceByName(userId, name) {
  const stmt = db.prepare('SELECT * FROM workspaces WHERE user_id = ? AND name = ?');
  return stmt.get(userId, name);
}

function deleteWorkspace(id) {
  const stmt = db.prepare('DELETE FROM workspaces WHERE id = ?');
  return stmt.run(id);
}

module.exports = {
  initialize,
  upsertUser,
  getUserById,
  getUserWorkspaces,
  createWorkspace,
  getWorkspace,
  getWorkspaceByName,
  updateWorkspaceStatus,
  updateWorkspaceContainer,
  deleteWorkspace
};
