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
const Docker = require('dockerode');

const { logger, createUserLogger } = require('./logger');
const db = require('./database');
const workspaceManager = require('./workspace-manager');
const workspaceEvents = require('./workspace-events');

const docker = new Docker();
const app = express();
const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN;
const TARGET_ORGANIZATION = process.env.TARGET_ORGANIZATION;
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
async function(accessToken, refreshToken, profile, done) {
  const userLogger = createUserLogger(profile.username);
  userLogger.info({ profileId: profile.id }, 'GitHub OAuth callback');
  
  try {
    // Check organization membership
    if (TARGET_ORGANIZATION) {
      userLogger.debug({ organization: TARGET_ORGANIZATION }, 'Checking organization membership');
      
      const https = require('https');
      const checkMembership = () => {
        return new Promise((resolve, reject) => {
          const options = {
            hostname: 'api.github.com',
            path: `/user/orgs`,
            method: 'GET',
            headers: {
              'Authorization': `token ${accessToken}`,
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
      
      const userOrgs = await checkMembership();
      const isMember = userOrgs.some(org => org.login === TARGET_ORGANIZATION);
      
      if (!isMember) {
        userLogger.warn({ username: profile.username, organization: TARGET_ORGANIZATION }, 'User is not a member of the required organization');
        return done(null, false, { 
          message: `ユーザー ${profile.username} は組織 ${TARGET_ORGANIZATION} に所属していません` 
        });
      }
      
      userLogger.info({ username: profile.username, organization: TARGET_ORGANIZATION }, 'Organization membership verified');
    }
    
    const user = {
      id: String(profile.id), // Ensure ID is string
      username: profile.username,
      displayName: profile.displayName,
      email: profile.emails && profile.emails[0] ? profile.emails[0].value : null,
      avatar: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
      githubAccessToken: accessToken
    };
    
    userLogger.debug({ user: { ...user, githubAccessToken: '[REDACTED]' } }, 'Storing user');
    // Store or update user in database
    db.upsertUser(user);
    
    return done(null, user);
  } catch (error) {
    userLogger.error({ error: error.message }, 'Error during OAuth callback');
    return done(error);
  }
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

// Auth routes with PKCE support
app.get('/auth/github', (req, res, next) => {
  // Generate state parameter for CSRF protection
  const state = crypto.randomBytes(32).toString('hex');
  req.session.oauthState = state;
  
  logger.info({ sessionId: req.sessionID, state }, 'OAuth initiated');
  
  passport.authenticate('github', {
    scope: ['user:email', 'read:org', 'repo'],
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
  (req, res, next) => {
    passport.authenticate('github', (err, user, info) => {
      const callbackLogger = logger.child({ sessionId: req.sessionID });
      
      if (err) {
        callbackLogger.error({ error: err.message }, 'Authentication error');
        return res.redirect('/?error=' + encodeURIComponent('認証中にエラーが発生しました'));
      }
      
      if (!user) {
        // Authentication failed (e.g., organization membership check failed)
        const errorMessage = info && info.message ? info.message : '認証に失敗しました';
        callbackLogger.warn({ info }, 'Authentication failed');
        return res.redirect('/?error=' + encodeURIComponent(errorMessage));
      }
      
      // Authentication successful
      req.logIn(user, (err) => {
        if (err) {
          callbackLogger.error({ error: err.message }, 'Login error');
          return res.redirect('/?error=' + encodeURIComponent('ログイン処理に失敗しました'));
        }
        callbackLogger.info({ username: user.username }, 'User logged in successfully');
        return res.redirect('/dashboard');
      });
    })(req, res, next);
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
        db.updateWorkspaceContainer(workspaceId, workspace.containerId, 'running');
        
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
    
    // Update status to building
    db.updateWorkspaceStatus(req.params.id, 'building');
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
        
        // Rebuild workspace (workspace directory already exists, just rebuild container)
        const newWorkspace = await workspaceManager.buildWorkspace(
          req.user.username,
          workspace.name,
          {}, // envVars - TODO: store and reuse
          req.params.id
        );
        
        // Update database with new container ID
        db.updateWorkspaceContainer(req.params.id, newWorkspace.containerId, 'running');
        
        // Update devcontainer build status if available
        if (newWorkspace.devcontainerBuildStatus) {
          db.updateWorkspaceDevcontainerBuildStatus(req.params.id, newWorkspace.devcontainerBuildStatus);
        }
        
        const updatedWorkspace = db.getWorkspace(req.params.id);
        workspaceEvents.publish(req.user.id, updatedWorkspace, 'updated');
        
        userLogger.info({ workspace: workspace.name }, 'Workspace rebuilt successfully');
      } catch (error) {
        userLogger.error({ workspace: workspace.name, error: error.message, stack: error.stack }, 'Error rebuilding workspace');
        
        db.updateWorkspaceStatus(req.params.id, 'failed');
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
app.listen(PORT, '0.0.0.0', () => {
  logger.info({ port: PORT, domain: DOMAIN }, 'Workspaces server started');
});
