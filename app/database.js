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
      devcontainer_build_status TEXT DEFAULT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      UNIQUE(user_id, name)
    );

    CREATE INDEX IF NOT EXISTS idx_workspaces_user_id ON workspaces(user_id);
  `);
  
  // Migration: Add devcontainer_build_status column if it doesn't exist
  try {
    const columns = db.prepare("PRAGMA table_info(workspaces)").all();
    const hasDevcontainerBuildStatus = columns.some(col => col.name === 'devcontainer_build_status');
    
    if (!hasDevcontainerBuildStatus) {
      db.exec('ALTER TABLE workspaces ADD COLUMN devcontainer_build_status TEXT DEFAULT NULL');
      console.log('Migration: Added devcontainer_build_status column to workspaces table');
    }
  } catch (error) {
    console.error('Migration error:', error);
  }
  
  // Migration: Add github_access_token column to users table if it doesn't exist
  try {
    const userColumns = db.prepare("PRAGMA table_info(users)").all();
    const hasGithubAccessToken = userColumns.some(col => col.name === 'github_access_token');
    
    if (!hasGithubAccessToken) {
      db.exec('ALTER TABLE users ADD COLUMN github_access_token TEXT DEFAULT NULL');
      console.log('Migration: Added github_access_token column to users table');
    }
  } catch (error) {
    console.error('Migration error:', error);
  }
}

function upsertUser(user) {
  const stmt = db.prepare(`
    INSERT INTO users (id, username, display_name, email, avatar, github_access_token, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
      username = excluded.username,
      display_name = excluded.display_name,
      email = excluded.email,
      avatar = excluded.avatar,
      github_access_token = excluded.github_access_token,
      updated_at = CURRENT_TIMESTAMP
  `);
  
  return stmt.run(user.id, user.username, user.displayName, user.email, user.avatar, user.githubAccessToken);
}

function getUserById(id) {
  const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
  return stmt.get(id);
}

function getUserWorkspaces(userId) {
  const stmt = db.prepare('SELECT * FROM workspaces WHERE user_id = ? ORDER BY created_at DESC');
  return stmt.all(userId);
}

function getAllWorkspaces() {
  const stmt = db.prepare('SELECT * FROM workspaces ORDER BY created_at DESC');
  return stmt.all();
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

function updateWorkspaceDevcontainerBuildStatus(id, buildStatus) {
  const stmt = db.prepare('UPDATE workspaces SET devcontainer_build_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
  return stmt.run(buildStatus, id);
}

module.exports = {
  initialize,
  upsertUser,
  getUserById,
  getUserWorkspaces,
  getAllWorkspaces,
  createWorkspace,
  getWorkspace,
  getWorkspaceByName,
  updateWorkspaceStatus,
  updateWorkspaceContainer,
  updateWorkspaceDevcontainerBuildStatus,
  deleteWorkspace
};
