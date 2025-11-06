require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const { logger, createUserLogger } = require('./logger');
const db = require('./database');
const workspaceManager = require('./workspace-manager');
const workspaceEvents = require('./workspace-events');

const app = express();
const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN;
const CALLBACK_URL = `https://${DOMAIN}/auth/github/callback`;

// Trust proxy (Nginx reverse proxy)
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Allow inline scripts for simplicity
}));

app.use(cors({
  origin: `https://${DOMAIN}`,
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  skip: (req) => {
    // Skip rate limiting for SSE endpoint
    return req.path === '/workspaces/events' || req.url === '/workspaces/events';
  }
});
app.use('/api/', limiter);

// Body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax' // Important for OAuth callback
  },
  proxy: true // Trust proxy (Nginx)
}));

// Passport configuration
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: CALLBACK_URL
},
function(accessToken, refreshToken, profile, done) {
  const userLogger = createUserLogger(profile.username);
  userLogger.info({ profileId: profile.id }, 'GitHub OAuth callback');
  
  const user = {
    id: String(profile.id), // Ensure ID is string
    username: profile.username,
    displayName: profile.displayName,
    email: profile.emails && profile.emails[0] ? profile.emails[0].value : null,
    avatar: profile.photos && profile.photos[0] ? profile.photos[0].value : null
  };
  
  userLogger.debug({ user }, 'Storing user');
  // Store or update user in database
  db.upsertUser(user);
  
  return done(null, user);
}
));

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

// Auth routes with PKCE support
app.get('/auth/github', (req, res, next) => {
  // Generate state parameter for CSRF protection
  const state = crypto.randomBytes(32).toString('hex');
  req.session.oauthState = state;
  
  logger.info({ sessionId: req.sessionID, state }, 'OAuth initiated');
  
  passport.authenticate('github', {
    scope: ['user:email'],
    state: state
  })(req, res, next);
});

app.get('/auth/github/callback',
  (req, res, next) => {
    const callbackLogger = logger.child({ 
      sessionId: req.sessionID,
      queryState: req.query.state,
      sessionState: req.session.oauthState
    });
    
    callbackLogger.debug('OAuth callback received');
    
    // Verify state parameter
    if (req.query.state !== req.session.oauthState) {
      callbackLogger.error('State mismatch in OAuth callback');
      return res.status(403).send('Invalid state parameter. Please try logging in again.');
    }
    delete req.session.oauthState;
    next();
  },
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/dashboard');
  }
);

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
    const { name, repoUrl, envVars } = req.body;
    
    if (!name || !repoUrl) {
      userLogger.warn({ name, repoUrl }, 'Invalid workspace creation request');
      return res.status(400).json({ error: 'Name and repository URL are required' });
    }
    
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
          workspaceId
        );
        
        // Update database with container ID and status
        db.updateWorkspaceContainer(workspaceId, workspace.containerId, 'running');
        
        const updatedWorkspace = db.getWorkspace(workspaceId);
        workspaceEvents.publish(req.user.id, updatedWorkspace, 'updated');
        
        userLogger.info({ workspace: name, containerId: workspace.containerId }, 'Workspace created successfully');
      } catch (error) {
        userLogger.error({ workspace: name, error: error.message, stack: error.stack }, 'Error creating workspace');
        
        // Update status to failed
        db.updateWorkspaceStatus(workspaceId, 'failed');
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
  
  if (!workspace || workspace.user_id !== req.user.id) {
    return res.status(404).json({ error: 'Workspace not found' });
  }
  
  res.json(workspace);
});

// Delete workspace
app.delete('/api/workspaces/:id', ensureAuthenticatedAPI, async (req, res) => {
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
    
    userLogger.info({ workspace: workspace.name, containerId: workspace.container_id }, 'Starting workspace deletion');
    
    // Update status to deleting
    db.updateWorkspaceStatus(req.params.id, 'deleting');
    const deletingWorkspace = db.getWorkspace(req.params.id);
    workspaceEvents.publish(req.user.id, deletingWorkspace, 'updated');
    
    // Return immediately
    res.json({ success: true, status: 'deleting' });
    
    // Async deletion
    (async () => {
      try {
        // Stop and remove container
        if (workspace.container_id) {
          await workspaceManager.deleteWorkspace(workspace.container_id);
        }
        
        // Remove from database
        db.deleteWorkspace(req.params.id);
        
        // Publish deleted event with numeric ID
        workspaceEvents.publish(req.user.id, { id: parseInt(req.params.id, 10) }, 'deleted');
        
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

// Start workspace
app.post('/api/workspaces/:id/start', ensureAuthenticatedAPI, async (req, res) => {
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
    
    // Check if workspace is already running
    if (workspace.status === 'running') {
      userLogger.warn({ workspace: workspace.name }, 'Workspace is already running');
      return res.status(409).json({ error: 'Workspace is already running' });
    }
    
    userLogger.info({ workspace: workspace.name, containerId: workspace.container_id }, 'Starting workspace');
    
    // Update status to starting
    db.updateWorkspaceStatus(req.params.id, 'starting');
    const startingWorkspace = db.getWorkspace(req.params.id);
    workspaceEvents.publish(req.user.id, startingWorkspace, 'updated');
    
    // Return immediately
    res.json({ success: true, status: 'starting' });
    
    // Async start
    (async () => {
      try {
        await workspaceManager.startWorkspace(workspace.container_id);
        db.updateWorkspaceStatus(req.params.id, 'running');
        
        const runningWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, runningWorkspace, 'updated');
        
        userLogger.info({ workspace: workspace.name }, 'Workspace started successfully');
      } catch (error) {
        userLogger.error({ workspace: workspace.name, error: error.message, stack: error.stack }, 'Error starting workspace');
        
        db.updateWorkspaceStatus(req.params.id, 'stopped');
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
    
    // Update status to stopping
    db.updateWorkspaceStatus(req.params.id, 'stopping');
    const stoppingWorkspace = db.getWorkspace(req.params.id);
    workspaceEvents.publish(req.user.id, stoppingWorkspace, 'updated');
    
    // Return immediately
    res.json({ success: true, status: 'stopping' });
    
    // Async stop
    (async () => {
      try {
        await workspaceManager.stopWorkspace(workspace.container_id);
        db.updateWorkspaceStatus(req.params.id, 'stopped');
        
        const stoppedWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, stoppedWorkspace, 'updated');
        
        userLogger.info({ workspace: workspace.name }, 'Workspace stopped successfully');
      } catch (error) {
        userLogger.error({ workspace: workspace.name, error: error.message, stack: error.stack }, 'Error stopping workspace');
        
        db.updateWorkspaceStatus(req.params.id, 'running');
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

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Initialize database
db.initialize();

// Start server
app.listen(PORT, '0.0.0.0', () => {
  logger.info({ port: PORT, domain: DOMAIN }, 'Pseudo CodeSpaces server started');
});
