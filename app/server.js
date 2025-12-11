// Load .env file only in development (not needed in Docker with env_file)
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const Docker = require('dockerode');

const { logger, createUserLogger } = require('./logger');
const db = require('./database');
const workspaceManager = require('./workspace-manager');
const workspaceEvents = require('./workspace-events');

const docker = new Docker();
const app = express();
const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN;
const WS_DOMAIN = process.env.WS_DOMAIN;
const TARGET_ORGANIZATION = process.env.TARGET_ORGANIZATION;
const CALLBACK_URL = `https://${WS_DOMAIN}/auth/github/callback`;

// Debug: Log environment variables at startup
logger.info({
  NODE_ENV: process.env.NODE_ENV,
  WS_GITHUB_CLIENT_ID: process.env.WS_GITHUB_CLIENT_ID ? 'SET' : 'NOT SET',
  WS_GITHUB_CLIENT_SECRET: process.env.WS_GITHUB_CLIENT_SECRET ? 'SET' : 'NOT SET',
  DOMAIN,
  WS_DOMAIN,
  TARGET_ORGANIZATION
}, 'Environment variables at startup');

// Trust proxy (Nginx reverse proxy)
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Allow inline scripts for simplicity
}));

app.use(cors({
  origin: `https://${WS_DOMAIN}`,
  credentials: true
}));

// Body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting (applied selectively after auth verify endpoint)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  skip: (req) => {
    // Skip rate limiting for SSE endpoint
    return req.path === '/workspaces/events' || 
           req.url === '/workspaces/events';
  }
});

// Session configuration (domain-specific, not shared)
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax', // Important for OAuth callback
    path: '/' // Ensure cookie is available for all paths
    // No domain specified - cookie is specific to this subdomain only
  },
  proxy: true, // Trust proxy (Nginx)
  name: 'workspaces.sid' // Custom session cookie name for clarity
}));

// Import shared OAuth configuration
const { configureGitHubAuth, createOAuthRoutes } = require('./auth-common');

// Configure GitHub OAuth strategy with organization checking
configureGitHubAuth({
  passport,
  clientID: process.env.WS_GITHUB_CLIENT_ID,
  clientSecret: process.env.WS_GITHUB_CLIENT_SECRET,
  callbackURL: CALLBACK_URL,
  targetOrganization: TARGET_ORGANIZATION,
  logger,
  onAuthSuccess: (accessToken, profile) => {
    // Create user object from GitHub profile
    const user = {
      id: String(profile.id),
      username: profile.username,
      displayName: profile.displayName,
      email: profile.emails && profile.emails[0] ? profile.emails[0].value : null,
      avatar: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
      githubAccessToken: accessToken
    };
    
    // Store or update user in database
    db.upsertUser(user);
    
    // Return user object for passport
    return user;
  }
});

passport.serializeUser((user, done) => {
  logger.debug({ userId: user.id }, 'Serializing user');
  // Ensure ID is stored as string
  done(null, String(user.id));
});

passport.deserializeUser((id, done) => {
  logger.debug({ userId: id }, 'Deserializing user');
  // Ensure ID is queried as string
  const user = db.getUserById(String(id));
  if (user) {
    logger.debug({ username: user.username }, 'User deserialized');
  } else {
    logger.warn({ userId: id }, 'User not found during deserialization');
  }
  done(null, user);
});

app.use(passport.initialize());
app.use(passport.session());

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Explicit favicon route
app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'favicon.ico'));
});

// Middleware to check authentication for pages
function ensureAuthenticated(req, res, next) {
  const sessionLogger = logger.child({ 
    sessionId: req.sessionID,
    authenticated: req.isAuthenticated() 
  });
  
  if (req.isAuthenticated()) {
    sessionLogger.debug({ user: req.user.username }, 'Authentication successful');
    return next();
  }
  
  sessionLogger.info('Authentication failed, redirecting to /');
  res.redirect('/');
}

// Middleware to check authentication for API endpoints
function ensureAuthenticatedAPI(req, res, next) {
  const sessionLogger = logger.child({ 
    sessionId: req.sessionID,
    authenticated: req.isAuthenticated() 
  });
  
  if (req.isAuthenticated()) {
    sessionLogger.debug({ user: req.user.username }, 'API authentication successful');
    return next();
  }
  
  sessionLogger.info('API authentication failed, returning 401');
  res.status(401).json({ 
    error: 'Unauthorized',
    message: 'Please log in to continue',
    redirect: '/'
  });
}

// Routes

// Home page - redirect to auth if not logged in
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect('/dashboard');
  } else {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

// Authentication verification endpoint for nginx auth_request (NO rate limiting)
app.get('/api/auth/verify', (req, res) => {
  if (req.isAuthenticated()) {
    res.status(200).send('OK');
  } else {
    res.status(401).send('Unauthorized');
  }
});

// Apply rate limiting to other API endpoints (after auth verify)
app.use('/api/', limiter);

// Create OAuth routes using shared module
const { initiateAuth, handleCallback } = createOAuthRoutes({
  passport,
  logger,
  defaultReturnTo: '/dashboard',
  errorMessages: {
    authError: '認証中にエラーが発生しました',
    authFailed: '認証に失敗しました',
    loginError: 'ログイン処理に失敗しました'
  }
});

// Auth routes
app.get('/auth/github', initiateAuth);
app.get('/auth/github/callback', handleCallback);

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

// Dashboard
app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// API Routes

// Get user's workspaces
app.get('/api/workspaces', ensureAuthenticatedAPI, (req, res) => {
  const workspaces = db.getUserWorkspaces(req.user.id);
  res.json(workspaces);
});

// Create new workspace (async)
app.post('/api/workspaces', ensureAuthenticatedAPI, async (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  
  try {
    const { name, envVars } = req.body;
    
    if (!name) {
      userLogger.warn({ name }, 'Invalid workspace creation request');
      return res.status(400).json({ error: 'Workspace name is required' });
    }
    
    // Get user's GitHub access token
    const user = db.getUserById(req.user.id);
    if (!user || !user.github_access_token) {
      userLogger.error({ userId: req.user.id }, 'User GitHub access token not found');
      return res.status(500).json({ error: 'GitHub access token not found. Please log out and log in again.' });
    }
    
    // Generate clean repository URL (without credentials for database storage)
    const repoUrl = `https://github.com/${TARGET_ORGANIZATION}/${name}.git`;
    userLogger.debug({ workspaceName: name, organization: TARGET_ORGANIZATION }, 'Generated repository URL');
    
    // Validate workspace name
    if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
      userLogger.warn({ name }, 'Invalid workspace name format');
      return res.status(400).json({ error: 'Invalid workspace name. Use only alphanumeric characters, hyphens, and underscores.' });
    }
    
    // Check if workspace already exists
    const existing = db.getWorkspaceByName(req.user.id, name);
    if (existing) {
      userLogger.warn({ workspace: name }, 'Workspace already exists');
      return res.status(409).json({ error: 'Workspace with this name already exists' });
    }
    
    userLogger.info({ workspace: name, repoUrl }, 'Starting workspace creation');
    
    // Create workspace record with 'building' status
    const workspaceId = db.createWorkspace({
      userId: req.user.id,
      name: name,
      repoUrl: repoUrl,
      containerId: null,
      status: 'building'
    });

    db.updateWorkspaceEnvVars(workspaceId, JSON.stringify(envVars || {}));
    
    const workspaceRecord = db.getWorkspace(workspaceId);
    
    // Immediately return to client
    res.json({
      id: workspaceId,
      name: name,
      status: 'building',
      message: 'Workspace creation started'
    });
    
    // Publish initial state
    workspaceEvents.publish(req.user.id, workspaceRecord, 'created');
    
    // Start async build process
    (async () => {
      try {
        const workspace = await workspaceManager.createWorkspace(
          req.user.username,
          name,
          repoUrl,
          envVars || {},
          workspaceId,
          user.github_access_token // Pass access token for git clone
        );
        
        // Update database with container ID and status
        const updateResult = db.updateWorkspaceContainer(workspaceId, workspace.containerId, 'running', 'building');
        if (updateResult.changes === 0) {
          userLogger.error({ workspace: name, containerId: workspace.containerId }, 'CRITICAL: Failed to update status to running after creation - concurrent modification');
          // Continue anyway - container is running
        }
        
        // Update devcontainer build status if available
        if (workspace.devcontainerBuildStatus) {
          db.updateWorkspaceDevcontainerBuildStatus(workspaceId, workspace.devcontainerBuildStatus);
        }
        
        const updatedWorkspace = db.getWorkspace(workspaceId);
        workspaceEvents.publish(req.user.id, updatedWorkspace, 'updated');
        
        userLogger.info({ workspace: name, containerId: workspace.containerId }, 'Workspace created successfully');
      } catch (error) {
        userLogger.error({ workspace: name, error: error.message, stack: error.stack }, 'Error creating workspace');
        
        // Update status to failed
        const statusUpdate = db.updateWorkspaceStatus(workspaceId, 'failed', 'building');
        if (statusUpdate.changes === 0) {
          userLogger.error({ workspace: name }, 'CRITICAL: Failed to update status to failed after creation error - concurrent modification');
          // Continue anyway - need to notify user
        }
        
        const failedWorkspace = db.getWorkspace(workspaceId);
        workspaceEvents.publish(req.user.id, failedWorkspace, 'updated');
      }
    })().catch(err => {
      userLogger.error({ workspace: name, error: err.message, stack: err.stack }, 'Unhandled error in async workspace creation');
    });
  } catch (error) {
    userLogger.error({ error: error.message, stack: error.stack }, 'Error initiating workspace creation');
    res.status(500).json({ error: error.message });
  }
});

// SSE endpoint for workspace updates (MUST be before :id route)
app.get('/api/workspaces/events', ensureAuthenticatedAPI, (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  userLogger.info('SSE connection established');
  
  // Set headers for SSE
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // Disable nginx buffering
  
  // Send initial connection message
  res.write(': connected\n\n');
  
  // Subscribe to workspace events
  workspaceEvents.subscribe(req.user.id, res);
  
  // Send current workspaces immediately
  const workspaces = db.getUserWorkspaces(req.user.id);
  res.write(`data: ${JSON.stringify({ type: 'init', workspaces: workspaces })}\n\n`);
  
  // Handle client disconnect
  req.on('close', () => {
    userLogger.info('SSE connection closed');
    workspaceEvents.unsubscribe(req.user.id, res);
  });
});

// Get workspace details
app.get('/api/workspaces/:id', ensureAuthenticatedAPI, (req, res) => {
  const workspace = db.getWorkspace(req.params.id);
  
  // User can view their own workspaces or released (shared) workspaces
  if (!workspace || (workspace.user_id !== req.user.id && workspace.user_id !== null)) {
    return res.status(404).json({ error: 'Workspace not found' });
  }
  
  res.json(workspace);
});

// Delete workspace
app.delete('/api/workspaces/:id', ensureAuthenticatedAPI, async (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  
  try {
    const workspace = db.getWorkspace(req.params.id);
    
    // User can delete their own workspaces or released workspaces (acquire then delete)
    if (!workspace) {
      userLogger.warn({ workspaceId: req.params.id }, 'Workspace not found');
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    // If workspace is released (user_id is NULL), acquire it first
    if (workspace.user_id === null) {
      const acquireResult = db.acquireWorkspace(req.params.id, req.user.id, workspace.status);
      if (acquireResult.changes === 0) {
        userLogger.warn({ workspaceId: req.params.id, workspaceName: workspace.name }, 'Failed to acquire workspace for deletion - already acquired by another user');
        return res.status(409).json({ error: 'Workspace is already being used by another user' });
      }
      userLogger.info({ workspace: workspace.name }, 'Workspace acquired for deletion');
      // Refresh workspace data
      workspace.user_id = req.user.id;
    } else if (workspace.user_id !== req.user.id) {
      userLogger.warn({ workspaceId: req.params.id }, 'Access denied - workspace owned by another user');
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Check if workspace is in a processing state
    const processingStates = ['building', 'starting', 'stopping', 'deleting'];
    if (processingStates.includes(workspace.status)) {
      userLogger.warn({ workspace: workspace.name, status: workspace.status }, 'Workspace is currently processing');
      return res.status(409).json({ error: `Workspace is currently ${workspace.status}` });
    }
    
    userLogger.info({ workspace: workspace.name, containerId: workspace.container_id }, 'Starting workspace deletion');
    
    // Update status to deleting with atomic check
    const updateResult = db.updateWorkspaceStatus(req.params.id, 'deleting', workspace.status);
    if (updateResult.changes === 0) {
      userLogger.warn({ workspace: workspace.name, currentStatus: workspace.status }, 'Failed to update status to deleting - concurrent modification detected');
      return res.status(409).json({ error: '操作が競合しました。ページを再読み込みしてください。' });
    }
    
    const deletingWorkspace = db.getWorkspace(req.params.id);
    workspaceEvents.publish(req.user.id, deletingWorkspace, 'updated');
    
    // Return immediately
    res.json({ success: true, status: 'deleting' });
    
    // Async deletion
    (async () => {
      try {
        // Stop and remove container (only if it exists)
        if (workspace.container_id) {
          try {
            await workspaceManager.deleteWorkspace(workspace.container_id);
          } catch (error) {
            // Container might not exist if build failed - log but continue with deletion
            userLogger.warn({ workspace: workspace.name, containerId: workspace.container_id, error: error.message }, 'Container not found or already removed, continuing with deletion');
            
            // Manually clean up workspace directory and nginx config since container doesn't exist
            try {
              await workspaceManager.cleanupWorkspaceFiles(req.user.username, workspace.name);
              userLogger.info({ workspace: workspace.name }, 'Workspace files cleaned up manually');
            } catch (cleanupError) {
              userLogger.warn({ workspace: workspace.name, error: cleanupError.message }, 'Failed to clean up workspace files');
            }
          }
        } else {
          // No container ID - just clean up workspace directory
          try {
            await workspaceManager.cleanupWorkspaceFiles(req.user.username, workspace.name);
            userLogger.info({ workspace: workspace.name }, 'Workspace files cleaned up (no container)');
          } catch (cleanupError) {
            userLogger.warn({ workspace: workspace.name, error: cleanupError.message }, 'Failed to clean up workspace files');
          }
        }
        
        // Remove from database
        db.deleteWorkspace(req.params.id);
        
        // Publish deleted event with numeric ID to the deleting user
        workspaceEvents.publish(req.user.id, { id: parseInt(req.params.id, 10) }, 'deleted');
        
        // Broadcast deleted event to all users (for released workspaces that others may be viewing)
        workspaceEvents.broadcastToAll({ id: parseInt(req.params.id, 10) }, 'deleted');
        
        userLogger.info({ workspace: workspace.name }, 'Workspace deleted successfully');
      } catch (error) {
        userLogger.error({ workspace: workspace.name, error: error.message, stack: error.stack }, 'Error deleting workspace');
        
        // Revert status
        db.updateWorkspaceStatus(req.params.id, 'stopped');
        const failedWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, failedWorkspace, 'updated');
      }
    })().catch(err => {
      userLogger.error({ error: err.message, stack: err.stack }, 'Unhandled error in async deletion');
    });
  } catch (error) {
    userLogger.error({ error: error.message, stack: error.stack }, 'Error initiating workspace deletion');
    res.status(500).json({ error: error.message });
  }
});

// Acquire workspace (for released/stopped workspaces) and start immediately
app.post('/api/workspaces/:id/acquire', ensureAuthenticatedAPI, async (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  
  try {
    const workspace = db.getWorkspace(req.params.id);
    
    if (!workspace) {
      userLogger.warn({ workspaceId: req.params.id }, 'Workspace not found');
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    // Can only acquire released workspaces (user_id is NULL)
    if (workspace.user_id !== null) {
      userLogger.warn({ workspaceId: req.params.id, workspaceName: workspace.name, ownerId: workspace.user_id }, 'Workspace is already owned');
      return res.status(409).json({ error: 'Workspace is already owned by a user' });
    }
    
    // Can only acquire stopped workspaces
    if (workspace.status !== 'stopped') {
      userLogger.warn({ workspace: workspace.name, status: workspace.status }, 'Workspace must be stopped to acquire');
      return res.status(409).json({ error: 'Workspace must be stopped to acquire' });
    }
    
    // Atomically acquire the workspace
    const result = db.acquireWorkspace(req.params.id, req.user.id, 'stopped');
    
    if (result.changes === 0) {
      userLogger.warn({ workspace: workspace.name }, 'Failed to acquire workspace - already acquired by another user');
      return res.status(409).json({ error: 'Workspace was just acquired by another user' });
    }
    
    userLogger.info({ workspace: workspace.name }, 'Workspace acquired successfully, starting immediately');
    
    // Update status to starting with atomic check
    const updateResult = db.updateWorkspaceStatus(req.params.id, 'starting', 'stopped');
    if (updateResult.changes === 0) {
      userLogger.warn({ workspace: workspace.name }, 'Failed to update status to starting - concurrent modification detected');
      return res.status(409).json({ error: '操作が競合しました。ページを再読み込みしてください。' });
    }
    
    const startingWorkspace = db.getWorkspace(req.params.id);
    
    // Notify the new owner
    workspaceEvents.publish(req.user.id, startingWorkspace, 'updated');
    
    // Notify all other users that this workspace is no longer available
    workspaceEvents.broadcastToAll(startingWorkspace, 'updated');
    
    // Return immediately
    res.json({ success: true, status: 'starting' });
    
    // Async start
    (async () => {
      try {
        await workspaceManager.startWorkspace(workspace.container_id);
        
        // Create nginx config for the new user
        try {
          await workspaceManager.updateNginxConfig(req.user.username, workspace.name, workspace.container_id);
          userLogger.info({ workspace: workspace.name }, 'Nginx config created for new user after acquisition');
        } catch (nginxError) {
          userLogger.error({ workspace: workspace.name, error: nginxError.message }, 'Failed to create nginx config after acquisition');
        }
        
        const statusUpdate = db.updateWorkspaceStatus(req.params.id, 'running', 'starting');
        if (statusUpdate.changes === 0) {
          userLogger.error({ workspace: workspace.name, workspaceId: req.params.id }, 'CRITICAL: Failed to update status to running after start - concurrent modification');
          // Continue anyway - container is running
        }
        
        const runningWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, runningWorkspace, 'updated');
        
        userLogger.info({ workspace: workspace.name }, 'Workspace started successfully after acquisition');
      } catch (error) {
        userLogger.error({ workspace: workspace.name, error: error.message, stack: error.stack }, 'Error starting workspace after acquisition');
        
        const statusUpdate = db.updateWorkspaceStatus(req.params.id, 'stopped', 'starting');
        if (statusUpdate.changes === 0) {
          userLogger.error({ workspace: workspace.name, workspaceId: req.params.id }, 'CRITICAL: Failed to revert status to stopped after start failure - concurrent modification');
        }
        
        const failedWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, failedWorkspace, 'updated');
      }
    })().catch(err => {
      userLogger.error({ workspace: workspace.name, error: err.message, stack: err.stack }, 'Unhandled error in async workspace start after acquisition');
    });
  } catch (error) {
    userLogger.error({ error: error.message, stack: error.stack }, 'Error acquiring workspace');
    res.status(500).json({ error: error.message });
  }
});

// Start workspace
app.post('/api/workspaces/:id/start', ensureAuthenticatedAPI, async (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  
  try {
    const workspace = db.getWorkspace(req.params.id);
    
    if (!workspace) {
      userLogger.warn({ workspaceId: req.params.id }, 'Workspace not found');
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    // If workspace is released (user_id is NULL), acquire it first
    if (workspace.user_id === null) {
      const acquireResult = db.acquireWorkspace(req.params.id, req.user.id, workspace.status);
      if (acquireResult.changes === 0) {
        userLogger.warn({ workspaceId: req.params.id, workspaceName: workspace.name }, 'Failed to acquire workspace for starting - already acquired by another user');
        return res.status(409).json({ error: 'Workspace is already being used by another user' });
      }
      userLogger.info({ workspace: workspace.name }, 'Workspace acquired for starting');
      // Refresh workspace data
      workspace.user_id = req.user.id;
    } else if (workspace.user_id !== req.user.id) {
      userLogger.warn({ workspaceId: req.params.id }, 'Access denied - workspace owned by another user');
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Check if workspace is in a processing state
    const processingStates = ['building', 'starting', 'stopping', 'deleting'];
    if (processingStates.includes(workspace.status)) {
      userLogger.warn({ workspace: workspace.name, status: workspace.status }, 'Workspace is currently processing');
      return res.status(409).json({ error: `Workspace is currently ${workspace.status}` });
    }
    
    // Check if workspace is already running
    if (workspace.status === 'running') {
      userLogger.warn({ workspace: workspace.name }, 'Workspace is already running');
      return res.status(409).json({ error: 'Workspace is already running' });
    }
    
    userLogger.info({ workspace: workspace.name, containerId: workspace.container_id }, 'Starting workspace');
    
    // Update status to starting with atomic check
    const updateResult = db.updateWorkspaceStatus(req.params.id, 'starting', workspace.status);
    if (updateResult.changes === 0) {
      userLogger.warn({ workspace: workspace.name, currentStatus: workspace.status }, 'Failed to update status to starting - concurrent modification detected');
      return res.status(409).json({ error: '操作が競合しました。ページを再読み込みしてください。' });
    }
    
    const startingWorkspace = db.getWorkspace(req.params.id);
    workspaceEvents.publish(req.user.id, startingWorkspace, 'updated');
    
    // Return immediately
    res.json({ success: true, status: 'starting' });
    
    // Async start
    (async () => {
      try {
        await workspaceManager.startWorkspace(workspace.container_id);
        
        // Create/update nginx config for the current user
        try {
          await workspaceManager.updateNginxConfig(req.user.username, workspace.name, workspace.container_id);
          userLogger.info({ workspace: workspace.name }, 'Nginx config created/updated on start');
        } catch (nginxError) {
          userLogger.error({ workspace: workspace.name, error: nginxError.message }, 'Failed to create/update nginx config on start');
        }
        
        const statusUpdate = db.updateWorkspaceStatus(req.params.id, 'running', 'starting');
        if (statusUpdate.changes === 0) {
          userLogger.error({ workspace: workspace.name, workspaceId: req.params.id }, 'CRITICAL: Failed to update status to running after start - concurrent modification');
          // Continue anyway - container is running
        }
        
        const runningWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, runningWorkspace, 'updated');
        
        userLogger.info({ workspace: workspace.name }, 'Workspace started successfully');
      } catch (error) {
        userLogger.error({ workspace: workspace.name, error: error.message, stack: error.stack }, 'Error starting workspace');
        
        const statusUpdate = db.updateWorkspaceStatus(req.params.id, 'stopped', 'starting');
        if (statusUpdate.changes === 0) {
          userLogger.error({ workspace: workspace.name, workspaceId: req.params.id }, 'CRITICAL: Failed to revert status to stopped after start failure - concurrent modification');
        }
        
        const failedWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, failedWorkspace, 'updated');
      }
    })().catch(err => {
      userLogger.error({ workspace: workspace.name, error: err.message, stack: err.stack }, 'Unhandled error in async workspace start');
    });
  } catch (error) {
    userLogger.error({ error: error.message, stack: error.stack }, 'Error initiating workspace start');
    res.status(500).json({ error: error.message });
  }
});

// Stop workspace
app.post('/api/workspaces/:id/stop', ensureAuthenticatedAPI, async (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  
  try {
    const workspace = db.getWorkspace(req.params.id);
    
    if (!workspace || workspace.user_id !== req.user.id) {
      userLogger.warn({ workspaceId: req.params.id }, 'Workspace not found or access denied');
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    // Check if workspace is in a processing state
    const processingStates = ['building', 'starting', 'stopping', 'deleting'];
    if (processingStates.includes(workspace.status)) {
      userLogger.warn({ workspace: workspace.name, status: workspace.status }, 'Workspace is currently processing');
      return res.status(409).json({ error: `Workspace is currently ${workspace.status}` });
    }
    
    // Check if workspace is already stopped
    if (workspace.status === 'stopped' || workspace.status === 'failed') {
      userLogger.warn({ workspace: workspace.name, status: workspace.status }, 'Workspace is not running');
      return res.status(409).json({ error: 'Workspace is not running' });
    }
    
    userLogger.info({ workspace: workspace.name, containerId: workspace.container_id }, 'Stopping workspace');
    
    // Update status to stopping with atomic check
    const updateResult = db.updateWorkspaceStatus(req.params.id, 'stopping', workspace.status);
    if (updateResult.changes === 0) {
      userLogger.warn({ workspace: workspace.name, currentStatus: workspace.status }, 'Failed to update status to stopping - concurrent modification detected');
      return res.status(409).json({ error: '操作が競合しました。ページを再読み込みしてください。' });
    }
    
    const stoppingWorkspace = db.getWorkspace(req.params.id);
    workspaceEvents.publish(req.user.id, stoppingWorkspace, 'updated');
    
    // Return immediately
    res.json({ success: true, status: 'stopping' });
    
    // Async stop
    (async () => {
      try {
        await workspaceManager.stopWorkspace(workspace.container_id);
        
        // Remove nginx config for the current user (will be recreated for new user on acquire)
        try {
          await workspaceManager.removeNginxConfig(req.user.username, workspace.name);
          userLogger.info({ workspace: workspace.name }, 'Nginx config removed on release');
        } catch (nginxError) {
          userLogger.warn({ workspace: workspace.name, error: nginxError.message }, 'Failed to remove nginx config on release');
        }
        
        // Release workspace (set user_id to NULL) when stopped successfully
        const result = db.releaseWorkspace(req.params.id, req.user.id, 'stopping');
        
        if (result.changes === 0) {
          userLogger.error({ workspace: workspace.name, workspaceId: req.params.id }, 'CRITICAL: Failed to release workspace - concurrent modification detected');
          // Revert to running state
          const revertUpdate = db.updateWorkspaceStatus(req.params.id, 'running', 'stopping');
          if (revertUpdate.changes === 0) {
            userLogger.error({ workspace: workspace.name, workspaceId: req.params.id }, 'CRITICAL: Failed to revert status to running - concurrent modification');
          }
          const failedWorkspace = db.getWorkspace(req.params.id);
          workspaceEvents.publish(req.user.id, failedWorkspace, 'updated');
          return;
        }
        
        // Update status to stopped
        const statusUpdate = db.updateWorkspaceStatus(req.params.id, 'stopped', 'stopping');
        if (statusUpdate.changes === 0) {
          userLogger.error({ workspace: workspace.name, workspaceId: req.params.id }, 'CRITICAL: Failed to update status to stopped after stop - concurrent modification');
          // Continue anyway - container is stopped
        }
        
        const stoppedWorkspace = db.getWorkspace(req.params.id);
        
        // Notify the original owner about release
        workspaceEvents.publish(req.user.id, stoppedWorkspace, 'updated');
        
        // Notify all users about newly available workspace (broadcast)
        workspaceEvents.broadcastToAll(stoppedWorkspace, 'updated');
        
        userLogger.info({ workspace: workspace.name }, 'Workspace stopped and released successfully');
      } catch (error) {
        userLogger.error({ workspace: workspace.name, error: error.message, stack: error.stack }, 'Error stopping workspace');
        
        const revertUpdate = db.updateWorkspaceStatus(req.params.id, 'running', 'stopping');
        if (revertUpdate.changes === 0) {
          userLogger.error({ workspace: workspace.name, workspaceId: req.params.id }, 'CRITICAL: Failed to revert status to running after stop failure - concurrent modification');
        }
        
        const failedWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, failedWorkspace, 'updated');
      }
    })().catch(err => {
      userLogger.error({ workspace: workspace.name, error: err.message, stack: err.stack }, 'Unhandled error in async workspace stop');
    });
  } catch (error) {
    userLogger.error({ error: error.message, stack: error.stack }, 'Error initiating workspace stop');
    res.status(500).json({ error: error.message });
  }
});

// Get workspace environment variables
app.get('/api/workspaces/:id/env-vars', ensureAuthenticatedAPI, async (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  
  try {
    const workspace = db.getWorkspace(req.params.id);
    
    if (!workspace || workspace.user_id !== req.user.id) {
      userLogger.warn({ workspaceId: req.params.id }, 'Workspace not found or access denied');
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    // Get env_vars from database (stored as JSON string)
    const envVars = workspace.env_vars ? JSON.parse(workspace.env_vars) : {};
    
    res.json({ envVars });
  } catch (error) {
    userLogger.error({ error: error.message, stack: error.stack }, 'Error fetching workspace environment variables');
    res.status(500).json({ error: error.message });
  }
});

// Update workspace environment variables
app.put('/api/workspaces/:id/env-vars', ensureAuthenticatedAPI, async (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  
  try {
    const { envVars } = req.body;
    const workspace = db.getWorkspace(req.params.id);
    
    if (!workspace || workspace.user_id !== req.user.id) {
      userLogger.warn({ workspaceId: req.params.id }, 'Workspace not found or access denied');
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    // Update env_vars in database (store as JSON string)
    db.updateWorkspaceEnvVars(req.params.id, JSON.stringify(envVars || {}));
    
    userLogger.info({ workspace: workspace.name, envVarsCount: Object.keys(envVars || {}).length }, 'Updated workspace environment variables');
    
    res.json({ success: true });
  } catch (error) {
    userLogger.error({ error: error.message, stack: error.stack }, 'Error updating workspace environment variables');
    res.status(500).json({ error: error.message });
  }
});

// Rebuild workspace
app.post('/api/workspaces/:id/rebuild', ensureAuthenticatedAPI, async (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  
  try {
    const workspace = db.getWorkspace(req.params.id);
    
    if (!workspace || workspace.user_id !== req.user.id) {
      userLogger.warn({ workspaceId: req.params.id }, 'Workspace not found or access denied');
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    // Check if workspace is in a processing state (except failed)
    const processingStates = ['building', 'starting', 'stopping', 'deleting'];
    if (processingStates.includes(workspace.status)) {
      userLogger.warn({ workspace: workspace.name, status: workspace.status }, 'Workspace is currently processing');
      return res.status(409).json({ error: `Workspace is currently ${workspace.status}` });
    }
    
    userLogger.info({ workspace: workspace.name, containerId: workspace.container_id }, 'Starting workspace rebuild');
    
    // Update status to building with atomic check
    const updateResult = db.updateWorkspaceStatus(req.params.id, 'building', workspace.status);
    if (updateResult.changes === 0) {
      userLogger.warn({ workspace: workspace.name, currentStatus: workspace.status }, 'Failed to update status to building - concurrent modification detected');
      return res.status(409).json({ error: '操作が競合しました。ページを再読み込みしてください。' });
    }
    
    const buildingWorkspace = db.getWorkspace(req.params.id);
    workspaceEvents.publish(req.user.id, buildingWorkspace, 'updated');
    
    // Return immediately
    res.json({ success: true, status: 'building' });
    
    // Async rebuild
    (async () => {
      try {
        // Stop and remove old container if exists
        if (workspace.container_id) {
          try {
            const docker = new Docker();
            const container = docker.getContainer(workspace.container_id);
            
            // Stop container
            try {
              await container.stop({ t: 10 });
              userLogger.info({ workspace: workspace.name, containerId: workspace.container_id }, 'Container stopped');
            } catch (error) {
              if (error.statusCode !== 304) { // 304 = already stopped
                throw error;
              }
            }
            
            // Remove container
            await container.remove({ force: true });
            userLogger.info({ workspace: workspace.name }, 'Old container removed');
          } catch (error) {
            userLogger.warn({ workspace: workspace.name, error: error.message }, 'Error removing old container (continuing)');
          }
        }
        
        // Get stored environment variables
        const envVars = workspace.env_vars ? JSON.parse(workspace.env_vars) : {};
        
        // Rebuild workspace (workspace directory already exists, just rebuild container)
        const newWorkspace = await workspaceManager.buildWorkspace(
          req.user.username,
          workspace.name,
          envVars,
          req.params.id
        );
        
        // Update database with new container ID
        const updateResult = db.updateWorkspaceContainer(req.params.id, newWorkspace.containerId, 'running', 'building');
        if (updateResult.changes === 0) {
          userLogger.error({ workspace: workspace.name, containerId: newWorkspace.containerId }, 'CRITICAL: Failed to update status to running after rebuild - concurrent modification');
          // Continue anyway - container is running
        }
        
        // Update devcontainer build status if available
        if (newWorkspace.devcontainerBuildStatus) {
          db.updateWorkspaceDevcontainerBuildStatus(req.params.id, newWorkspace.devcontainerBuildStatus);
        }
        
        const updatedWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, updatedWorkspace, 'updated');
        
        userLogger.info({ workspace: workspace.name }, 'Workspace rebuilt successfully');
      } catch (error) {
        userLogger.error({ workspace: workspace.name, error: error.message, stack: error.stack }, 'Error rebuilding workspace');
        
        const statusUpdate = db.updateWorkspaceStatus(req.params.id, 'failed', 'building');
        if (statusUpdate.changes === 0) {
          userLogger.error({ workspace: workspace.name }, 'CRITICAL: Failed to update status to failed after rebuild error - concurrent modification');
          // Continue anyway - need to notify user
        }
        
        const failedWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, failedWorkspace, 'updated');
      }
    })().catch(err => {
      userLogger.error({ error: err.message, stack: err.stack }, 'Unhandled error in async rebuild');
    });
  } catch (error) {
    userLogger.error({ error: error.message, stack: error.stack }, 'Error initiating workspace rebuild');
    res.status(500).json({ error: error.message });
  }
});

// Download build log (supports both GET and HEAD)
const buildLogHandler = async (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  
  try {
    const workspace = db.getWorkspace(req.params.id);
    
    if (!workspace || workspace.user_id !== req.user.id) {
      userLogger.warn({ workspaceId: req.params.id }, 'Workspace not found or access denied');
      return res.status(404).json({ error: 'Workspace not found' });
    }
    
    try {
      const logContent = await workspaceManager.readBuildLog(workspace.name);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${workspace.name}-build.log"`);
      
      // For HEAD requests, just send headers without body
      if (req.method === 'HEAD') {
        res.setHeader('Content-Length', Buffer.byteLength(logContent, 'utf8'));
        return res.end();
      }
      
      res.send(logContent);
      userLogger.debug({ workspace: workspace.name }, 'Build log downloaded');
    } catch (error) {
      if (error.message === 'Build log not found') {
        return res.status(404).json({ error: 'Build log not found' });
      }
      throw error;
    }
  } catch (error) {
    userLogger.error({ error: error.message, stack: error.stack }, 'Error downloading build log');
    res.status(500).json({ error: error.message });
  }
};

app.get('/api/workspaces/:id/build-log', ensureAuthenticatedAPI, buildLogHandler);
app.head('/api/workspaces/:id/build-log', ensureAuthenticatedAPI, buildLogHandler);

// Get current user info API
app.get('/api/user', ensureAuthenticatedAPI, (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    displayName: req.user.displayName,
    email: req.user.email,
    avatar: req.user.avatar
  });
});

// Get available repositories for workspace creation
app.get('/api/available-repositories', ensureAuthenticatedAPI, async (req, res) => {
  const userLogger = createUserLogger(req.user.username);
  
  try {
    // Get user's GitHub access token
    const user = db.getUserById(req.user.id);
    if (!user || !user.github_access_token) {
      userLogger.error({ userId: req.user.id }, 'User GitHub access token not found');
      return res.status(500).json({ error: 'GitHub access token not found. Please log out and log in again.' });
    }
    
    if (!TARGET_ORGANIZATION) {
      userLogger.error('TARGET_ORGANIZATION not configured');
      return res.status(500).json({ error: 'Target organization not configured' });
    }
    
    userLogger.info({ organization: TARGET_ORGANIZATION }, 'Fetching organization repositories');
    
    // Fetch organization repositories from GitHub API
    const https = require('https');
    const getOrgRepos = () => {
      return new Promise((resolve, reject) => {
        const options = {
          hostname: 'api.github.com',
          path: `/orgs/${TARGET_ORGANIZATION}/repos?per_page=100&type=all`,
          method: 'GET',
          headers: {
            'Authorization': `token ${user.github_access_token}`,
            'User-Agent': 'Workspaces-App',
            'Accept': 'application/vnd.github.v3+json'
          }
        };
        
        const req = https.request(options, (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            if (res.statusCode === 200) {
              resolve(JSON.parse(data));
            } else {
              reject(new Error(`GitHub API returned ${res.statusCode}: ${data}`));
            }
          });
        });
        
        req.on('error', reject);
        req.end();
      });
    };
    
    const repos = await getOrgRepos();
    userLogger.debug({ repoCount: repos.length }, 'Organization repositories fetched');
    
    // Get all existing workspaces (from all users)
    const allWorkspaces = db.getAllWorkspaces();
    const usedNames = new Set(allWorkspaces.map(ws => ws.name));
    
    userLogger.debug({ usedCount: usedNames.size }, 'Existing workspaces retrieved');
    
    // Filter repositories: only those not already used as workspaces
    const availableRepos = repos
      .filter(repo => !usedNames.has(repo.name))
      .map(repo => ({
        name: repo.name,
        description: repo.description,
        private: repo.private,
        url: repo.html_url
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
    
    userLogger.info({ availableCount: availableRepos.length, totalRepos: repos.length }, 'Available repositories calculated');
    
    res.json({
      repositories: availableRepos,
      organization: TARGET_ORGANIZATION
    });
  } catch (error) {
    userLogger.error({ error: error.message, stack: error.stack }, 'Error fetching available repositories');
    res.status(500).json({ error: error.message });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Initialize database
db.initialize();

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info({ port: PORT, domain: DOMAIN }, 'Workspaces server started');
});

// Graceful shutdown handler
async function gracefulShutdown(signal) {
  logger.info({ signal }, 'Received shutdown signal, starting graceful shutdown');
  
  // Stop accepting new connections
  server.close(() => {
    logger.info('HTTP server closed');
  });
  
  try {
    // Get all running workspaces
    const allWorkspaces = db.getAllWorkspaces();
    const runningWorkspaces = allWorkspaces.filter(ws => ws.status === 'running' && ws.user_id !== null);
    
    logger.info({ count: runningWorkspaces.length }, 'Stopping all running workspaces');
    
    // Stop all running workspaces in parallel
    const stopPromises = runningWorkspaces.map(async (workspace) => {
      try {
        logger.info({ workspace: workspace.name, containerId: workspace.container_id }, 'Stopping workspace');
        
        // Stop the container
        if (workspace.container_id) {
          await workspaceManager.stopWorkspace(workspace.container_id);
        }
        
        // Release workspace (set user_id to NULL)
        db.releaseWorkspace(workspace.id, workspace.user_id, 'running');
        
        // Update status to stopped
        db.updateWorkspaceStatus(workspace.id, 'stopped');
        
        logger.info({ workspace: workspace.name }, 'Workspace stopped and released');
      } catch (error) {
        logger.error({ workspace: workspace.name, error: error.message }, 'Error stopping workspace during shutdown');
      }
    });
    
    await Promise.all(stopPromises);
    
    logger.info('All workspaces stopped successfully');
  } catch (error) {
    logger.error({ error: error.message, stack: error.stack }, 'Error during graceful shutdown');
  }
  
  // Exit process
  logger.info('Graceful shutdown complete, exiting');
  process.exit(0);
}

// Register shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
