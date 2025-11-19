const Docker = require('dockerode');
const simpleGit = require('simple-git');
const fs = require('fs').promises;
const path = require('path');
const yaml = require('js-yaml');
const { exec, spawn } = require('child_process');
const { promisify } = require('util');
const { 
  logger, 
  createWorkspaceLogger, 
  createActionLogger,
  createContainerLogger 
} = require('./logger');

const execAsync = promisify(exec);
const docker = new Docker();

const WORKSPACES_BASE_DIR = '/home/codespace/workspaces';
const NGINX_CONFIG_DIR = '/opt/nginx-config';
const BUILD_LOGS_BASE_DIR = '/home/codespace/buildlogs';

async function createWorkspace(username, workspaceName, repoUrl, envVars = {}, workspaceId = null, githubAccessToken = null) {
  const wsLogger = createWorkspaceLogger(username, workspaceName);
  if (workspaceId) {
    wsLogger.info({ repoUrl, workspaceId }, 'Creating workspace');
  } else {
    wsLogger.info({ repoUrl }, 'Creating workspace');
  }
  
  const workspaceDir = path.join(WORKSPACES_BASE_DIR, workspaceName);
  
  // Check if workspace directory already exists
  try {
    await fs.access(workspaceDir);
    // Directory exists - try to remove it first
    wsLogger.warn({ workspaceDir }, 'Workspace directory already exists, removing it');
    try {
      await removeWorkspaceDirectory(workspaceDir, wsLogger);
      wsLogger.info({ workspaceDir }, 'Existing workspace directory removed');
    } catch (error) {
      wsLogger.error({ workspaceDir, error: error.message }, 'Failed to remove existing workspace directory');
      throw new Error(`Workspace directory already exists and could not be removed: ${workspaceDir}`);
    }
  } catch (error) {
    // Directory doesn't exist - this is expected
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
  
  // Create workspace directory
  await fs.mkdir(workspaceDir, { recursive: true });
  wsLogger.debug({ workspaceDir }, 'Workspace directory created');

  // Ensure workspace directory is owned by codespace so clone as codespace can write into it
  try {
    await execAsync(`chown -R codespace:codespace "${workspaceDir}"`);
  } catch (err) {
    wsLogger.warn({ error: err.message }, 'chown before clone failed (continuing)');
  }

  // Prepare build log early for clone errors
  await fs.mkdir(BUILD_LOGS_BASE_DIR, { recursive: true });
  const buildLogFile = getBuildLogPath(workspaceName);
  await fs.writeFile(buildLogFile, `Build log for ${workspaceName}\nStarted at: ${new Date().toISOString()}\n\n`);
  
  // Clone repository as codespace user
  const cloneLogger = createActionLogger(username, workspaceName, 'clone-repository');
  cloneLogger.info({ repoUrl }, 'Cloning repository as codespace');
  await writeToBuildLog(buildLogFile, `=== Cloning repository ===\n`);
  await writeToBuildLog(buildLogFile, `Repository URL: ${repoUrl}\n`);
  await writeToBuildLog(buildLogFile, `Workspace directory: ${workspaceDir}\n\n`);
  
  try {
    // Build authenticated URL for git clone if access token is provided
    let cloneUrl = repoUrl;
    if (githubAccessToken && repoUrl.startsWith('https://github.com/')) {
      cloneUrl = repoUrl.replace('https://github.com/', `https://x-oauth-basic:${githubAccessToken}@github.com/`);
      cloneLogger.debug('Using authenticated URL for clone');
    }
    
    // Use sudo -u codespace to perform the clone as the codespace user
    await execAsync(`sudo -u codespace git clone '${cloneUrl}' '${workspaceDir}'`, { maxBuffer: 10 * 1024 * 1024 });
    cloneLogger.info('Repository cloned successfully');
    await writeToBuildLog(buildLogFile, `✅ Repository cloned successfully\n\n`);
  } catch (err) {
    cloneLogger.error({ error: err.message, stderr: err.stderr, stdout: err.stdout }, 'Git clone failed');
    await writeToBuildLog(buildLogFile, `\n=== GIT CLONE FAILED ===\n`);
    await writeToBuildLog(buildLogFile, `Error: ${err.message}\n`);
    if (err.stderr) {
      await writeToBuildLog(buildLogFile, `\nStderr:\n${err.stderr}\n`);
    }
    if (err.stdout) {
      await writeToBuildLog(buildLogFile, `\nStdout:\n${err.stdout}\n`);
    }
    await writeToBuildLog(buildLogFile, `\nPlease check:\n`);
    await writeToBuildLog(buildLogFile, `  - Repository URL is correct and accessible\n`);
    await writeToBuildLog(buildLogFile, `  - Repository is public or you have access rights\n`);
    await writeToBuildLog(buildLogFile, `  - Network connectivity is working\n`);
    await writeToBuildLog(buildLogFile, `  - GitHub OAuth token has 'repo' scope for private repositories\n`);
    throw err;
  }
  
  // Check for devcontainer.json
  const devcontainerPath = path.join(workspaceDir, '.devcontainer', 'devcontainer.json');
  let hasDevcontainer = false;
  
  try {
    await fs.access(devcontainerPath);
    hasDevcontainer = true;
    wsLogger.info({ devcontainerPath }, 'devcontainer.json found');
  } catch (error) {
    wsLogger.info('No devcontainer.json found, using default devcontainer image');
  }
  
  // Always use Devcontainer CLI (with or without devcontainer.json)
  wsLogger.info('Using Devcontainer CLI to build and start workspace');
  return await buildWithDevcontainerCLI(workspaceDir, username, workspaceName, envVars, hasDevcontainer);
}

async function buildWithDevcontainerCLI(workspaceDir, username, workspaceName, envVars = {}, hasDevcontainer = false, retryWithDefault = false) {
  const buildLogger = createActionLogger(username, workspaceName, 'build-devcontainer');
  
  if (retryWithDefault) {
    buildLogger.info('Retrying build with default devcontainer image (original build failed)');
  } else {
    buildLogger.info('Building workspace with devcontainer CLI');
  }
  
  const containerName = `code-server-${workspaceName}`;
  const networkName = 'workspaces_internal';
  
  // Prepare build log
  await fs.mkdir(BUILD_LOGS_BASE_DIR, { recursive: true });
  const buildLogFile = getBuildLogPath(workspaceName);
  
  if (retryWithDefault) {
    await writeToBuildLog(buildLogFile, `\n\n${'='.repeat(80)}\n`);
    await writeToBuildLog(buildLogFile, `RETRYING WITH DEFAULT IMAGE\n`);
    await writeToBuildLog(buildLogFile, `${'='.repeat(80)}\n\n`);
  } else {
    // Check if build log already exists (created during clone)
    try {
      await fs.access(buildLogFile);
      // Log file exists, just append a separator
      await writeToBuildLog(buildLogFile, `\n${'='.repeat(80)}\n`);
      await writeToBuildLog(buildLogFile, `STARTING DEVCONTAINER BUILD\n`);
      await writeToBuildLog(buildLogFile, `${'='.repeat(80)}\n\n`);
    } catch (error) {
      // Log file doesn't exist, create it (for rebuild scenarios)
      await fs.writeFile(buildLogFile, `Build log for ${workspaceName}\nStarted at: ${new Date().toISOString()}\n\n`);
    }
  }
  
  // Build devcontainer up command
  let devcontainerCmd = `devcontainer up --workspace-folder "${workspaceDir}" --id-label workspaces.workspace=${workspaceName} --id-label workspaces.username=${username}`;
  
  // If no devcontainer.json, create a temporary one with default image
  // OR if retrying after failure, replace existing devcontainer.json with default
  let tempDevcontainerCreated = false;
  let originalDevcontainerBackup = null;
  
  // Always backup original devcontainer.json if it exists (to add runArgs with container name)
  const devcontainerDir = path.join(workspaceDir, '.devcontainer');
  const devcontainerPath = path.join(devcontainerDir, 'devcontainer.json');
  
  if (hasDevcontainer && !retryWithDefault) {
    try {
      const originalContent = await fs.readFile(devcontainerPath, 'utf8');
      originalDevcontainerBackup = originalContent;
      buildLogger.debug('Original devcontainer.json backed up');
      
      // Parse and modify devcontainer.json to add container name and network
      const devcontainerConfig = JSON.parse(originalContent);
      devcontainerConfig.runArgs = devcontainerConfig.runArgs || [];
      
      // Remove existing --name and --network options if present
      const filteredRunArgs = [];
      let i = 0;
      while (i < devcontainerConfig.runArgs.length) {
        const arg = devcontainerConfig.runArgs[i];
        if (arg === '--name' || arg === '--network') {
          // Skip this argument and its value
          i += 2;
        } else {
          filteredRunArgs.push(arg);
          i += 1;
        }
      }
      
      // Add our --name and --network options
      devcontainerConfig.runArgs = [
        ...filteredRunArgs,
        '--name', containerName,
        '--network', networkName
      ];
      
      await fs.writeFile(devcontainerPath, JSON.stringify(devcontainerConfig, null, 2));
      buildLogger.info({ containerName, networkName }, 'Added container name and network to devcontainer.json runArgs');
      await writeToBuildLog(buildLogFile, `Added --name ${containerName} and --network ${networkName} to devcontainer.json runArgs\n`);
    } catch (error) {
      buildLogger.warn({ error: error.message }, 'Failed to modify devcontainer.json, continuing without container name/network');
    }
  }
  
  if (!hasDevcontainer || retryWithDefault) {
    const defaultImage = 'mcr.microsoft.com/devcontainers/universal:2-linux';
    buildLogger.info({ defaultImage }, retryWithDefault ? 'Using default image as fallback' : 'Using default image');
    await writeToBuildLog(buildLogFile, `Using default image: ${defaultImage}\n`);
    
    // Backup original devcontainer.json if retrying
    if (retryWithDefault && hasDevcontainer && !originalDevcontainerBackup) {
      try {
        const originalContent = await fs.readFile(devcontainerPath, 'utf8');
        originalDevcontainerBackup = originalContent;
        await writeToBuildLog(buildLogFile, `Original devcontainer.json backed up\n`);
        buildLogger.debug('Original devcontainer.json backed up for potential restore');
      } catch (backupError) {
        buildLogger.warn({ error: backupError.message }, 'Could not backup original devcontainer.json');
      }
    }
    
    try {
      await fs.mkdir(devcontainerDir, { recursive: true });
      const devcontainerConfig = {
        name: containerName,
        image: defaultImage,
        runArgs: [
          '--name', containerName,
          '--network', networkName
        ],
        customizations: {
          vscode: {
            settings: {},
            extensions: []
          }
        }
      };
      await fs.writeFile(devcontainerPath, JSON.stringify(devcontainerConfig, null, 2));
      await writeToBuildLog(buildLogFile, retryWithDefault ? `Created fallback devcontainer.json\n` : `Created temporary devcontainer.json\n`);
      tempDevcontainerCreated = true;
    } catch (error) {
      buildLogger.error({ error: error.message }, 'Failed to create devcontainer.json');
      await writeToBuildLog(buildLogFile, `ERROR: Failed to create devcontainer.json: ${error.message}\n`);
      throw error;
    }
  } else {
    await writeToBuildLog(buildLogFile, 'Building with .devcontainer/devcontainer.json\n');
    
    // Validate devcontainer.json image name
    try {
      const devcontainerPath = path.join(workspaceDir, '.devcontainer', 'devcontainer.json');
      const devcontainerContent = await fs.readFile(devcontainerPath, 'utf8');
      const devcontainerConfig = JSON.parse(devcontainerContent);
      
      if (devcontainerConfig.image) {
        buildLogger.info({ image: devcontainerConfig.image }, 'Using image from devcontainer.json');
        await writeToBuildLog(buildLogFile, `Using image: ${devcontainerConfig.image}\n`);
        
        // Check for common typos in image names
        const imageName = devcontainerConfig.image;
        if (imageName.includes('bullseyex') || imageName.includes('bookwormx')) {
          buildLogger.warn({ image: imageName }, 'Suspicious image name detected - may contain typo');
          await writeToBuildLog(buildLogFile, `WARNING: Image name "${imageName}" looks suspicious. Did you mean "bullseye" or "bookworm" instead of ending with "x"?\n`);
        }
      }
    } catch (validationError) {
      buildLogger.debug({ error: validationError.message }, 'Could not validate devcontainer.json (may use Dockerfile)');
    }
  }
  
  await writeToBuildLog(buildLogFile, `\n=== Running devcontainer up ===\n`);
  buildLogger.debug({ command: devcontainerCmd }, 'Running devcontainer CLI');
  
  let tempDevcontainerPath = null;
  if (tempDevcontainerCreated) {
    tempDevcontainerPath = path.join(workspaceDir, '.devcontainer', 'devcontainer.json');
  }
  
  try {
    // Use spawn instead of execAsync to stream output in real-time
    const devcontainerArgs = [
      'up',
      '--workspace-folder', workspaceDir,
      '--id-label', `workspaces.workspace=${workspaceName}`,
      '--id-label', `workspaces.username=${username}`
    ];
    
    buildLogger.info({ args: devcontainerArgs }, 'Spawning devcontainer CLI process');
    await writeToBuildLog(buildLogFile, `Command: devcontainer ${devcontainerArgs.join(' ')}\n\n`);
    
    const devcontainerProcess = spawn('devcontainer', devcontainerArgs, {
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false
    });
    
    let stdoutBuffer = '';
    let stderrBuffer = '';
    let containerIdFromCLI = null;
    
    // Handle stdout - write to log in real-time and buffer for parsing
    devcontainerProcess.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      stdoutBuffer += text;
      
      // Write to build log immediately
      writeToBuildLog(buildLogFile, text).catch(err => 
        buildLogger.error({ error: err.message }, 'Failed to write stdout to build log')
      );
      
      // Try to parse each line for container ID
      const lines = text.split('\n');
      for (const line of lines) {
        if (line.trim()) {
          try {
            const json = JSON.parse(line);
            if (json.containerId && !containerIdFromCLI) {
              containerIdFromCLI = json.containerId;
              buildLogger.info({ containerId: containerIdFromCLI }, 'Container ID found in output');
            }
          } catch (e) {
            // Not JSON, that's fine
          }
        }
      }
    });
    
    // Handle stderr - write to log in real-time
    devcontainerProcess.stderr.on('data', (chunk) => {
      const text = chunk.toString();
      stderrBuffer += text;
      
      // Write to build log immediately with stderr marker
      writeToBuildLog(buildLogFile, `[stderr] ${text}`).catch(err => 
        buildLogger.error({ error: err.message }, 'Failed to write stderr to build log')
      );
    });
    
    // Wait for process to complete
    const exitCode = await new Promise((resolve, reject) => {
      devcontainerProcess.on('close', resolve);
      devcontainerProcess.on('error', reject);
    });
    
    if (exitCode !== 0) {
      const error = new Error(`devcontainer up exited with code ${exitCode}`);
      error.stdout = stdoutBuffer;
      error.stderr = stderrBuffer;
      error.exitCode = exitCode;
      throw error;
    }
    
    buildLogger.info({ exitCode }, 'devcontainer up completed successfully');
    await writeToBuildLog(buildLogFile, `\n=== devcontainer up completed (exit code: ${exitCode}) ===\n\n`);
    
    // Parse the stdout buffer to get container ID if not already found
    if (!containerIdFromCLI) {
      const lines = stdoutBuffer.split('\n');
      for (const line of lines) {
        try {
          const json = JSON.parse(line);
          if (json.containerId) {
            containerIdFromCLI = json.containerId;
            break;
          }
        } catch (e) {
          // Not JSON, continue
        }
      }
    }
    
    // Get the container
    let containerId = containerIdFromCLI;
    if (!containerId) {
      buildLogger.debug('Container ID not found in CLI output, searching by label');
      // Fallback: search by label
      const containers = await docker.listContainers({ all: true });
      const container = containers.find(c => 
        c.Labels && 
        c.Labels['workspaces.workspace'] === workspaceName &&
        c.Labels['workspaces.username'] === username
      );
      
      if (!container) {
        throw new Error(`Container for workspace ${workspaceName} not found after devcontainer up`);
      }
      containerId = container.Id;
    }
    
    const containerLogger = createContainerLogger(username, workspaceName, containerId);
    containerLogger.info('Container found');
    
    const containerObj = docker.getContainer(containerId);
    let containerInfo = await containerObj.inspect();
    
    // Check if container is running
    if (!containerInfo.State.Running) {
      containerLogger.info('Container not running, starting it');
      await containerObj.start();
      // Refresh container info after starting
      containerInfo = await containerObj.inspect();
    }
    
    // Verify container is on the correct network (network should already be configured via runArgs)
    const networkName = 'workspaces_internal';
    containerInfo = await containerObj.inspect();
    let networks = containerInfo.NetworkSettings.Networks;
    
    if (networks[networkName]) {
      containerLogger.info({ networkName }, 'Container is on the correct network');
    } else {
      containerLogger.warn({ networkName, actualNetworks: Object.keys(networks) }, 'Container is not on expected network - this may cause connectivity issues');
    }
    
    // Ensure UID 1000 user exists in container (codespace user)
    const uid1000Logger = createContainerLogger(username, workspaceName, containerInfo.Id, 'ensure-uid1000');
    await writeToBuildLog(buildLogFile, '\n=== Ensuring UID 1000 user exists ===\n');
    const uid1000User = await ensureUID1000User(containerObj, uid1000Logger);
    await writeToBuildLog(buildLogFile, `UID 1000 user: ${uid1000User}\n`);
    
    // Install code-server as root, then start it as UID 1000 user
    const installLogger = createActionLogger(username, workspaceName, 'setup-code-server');
    installLogger.info('Installing code-server as root');
    await writeToBuildLog(buildLogFile, '\n=== Installing code-server ===\n');
    
    // Step 1: Install code-server as root
    const installScript = `
      set -e
      echo "Starting code-server installation as root..."
      if ! command -v code-server &> /dev/null; then
        echo "code-server not found, installing..."
        curl -fsSL https://code-server.dev/install.sh | sh
        echo "code-server installed successfully"
      else
        echo "code-server already installed"
      fi
    `;
    
    const execInstall = await containerObj.exec({
      Cmd: ['/bin/sh', '-c', installScript],
      AttachStdout: true,
      AttachStderr: true,
      User: 'root'
    });
    
    const installStream = await execInstall.start({});
    
    // Collect and log install output
    await new Promise((resolve, reject) => {
      installStream.on('end', resolve);
      installStream.on('error', reject);
      installStream.on('data', (chunk) => {
        const text = chunk.toString();
        writeToBuildLog(buildLogFile, text).catch(err => 
          installLogger.error({ error: err.message }, 'Failed to write to build log')
        );
        if (text.includes('installed') || text.includes('ERROR')) {
          installLogger.info({ message: text.trim() }, 'code-server installation progress');
        } else {
          installLogger.debug({ message: text.trim() }, 'code-server installation output');
        }
      });
    });
    
    installLogger.info({ user: uid1000User }, 'Starting code-server as UID 1000 user (codespace)');
    await writeToBuildLog(buildLogFile, '\n=== Starting code-server ===\n');
    
    // Step 2: Start code-server as UID 1000 user
    const startScript = `
      set -e
      echo "Starting code-server on port 8080 as user ${uid1000User}..."
      nohup code-server --bind-addr 0.0.0.0:8080 --auth none /workspaces > /tmp/code-server.log 2>&1 &
      CODE_SERVER_PID=$!
      echo "code-server started with PID: $CODE_SERVER_PID"
      
      # Wait for code-server to be ready
      echo "Waiting for code-server to start..."
      i=1
      while [ $i -le 30 ]; do
        if nc -z localhost 8080 2>/dev/null || netstat -tuln 2>/dev/null | grep -q ':8080 '; then
          echo "code-server is ready on port 8080!"
          exit 0
        fi
        echo "Waiting... ($i/30)"
        sleep 1
        i=$((i + 1))
      done
      
      # Check if process is still running
      if kill -0 $CODE_SERVER_PID 2>/dev/null; then
        echo "code-server process is running (PID: $CODE_SERVER_PID) but not responding yet"
        echo "Checking logs..."
        tail -20 /tmp/code-server.log 2>/dev/null || echo "No logs available"
      else
        echo "ERROR: code-server process died!"
        echo "Logs:"
        cat /tmp/code-server.log 2>/dev/null || echo "No logs available"
        exit 1
      fi
      exit 0
    `;
    
    const execStart = await containerObj.exec({
      Cmd: ['/bin/sh', '-c', startScript],
      AttachStdout: true,
      AttachStderr: true,
      User: uid1000User
    });
    
    const startStream = await execStart.start({});
    
    // Collect and log start output
    await new Promise((resolve, reject) => {
      startStream.on('end', resolve);
      startStream.on('error', reject);
      startStream.on('data', (chunk) => {
        const text = chunk.toString();
        writeToBuildLog(buildLogFile, text).catch(err => 
          installLogger.error({ error: err.message }, 'Failed to write to build log')
        );
        if (text.includes('ready') || text.includes('ERROR') || text.includes('started')) {
          installLogger.info({ message: text.trim() }, 'code-server start progress');
        } else {
          installLogger.debug({ message: text.trim() }, 'code-server start output');
        }
      });
    });
    
    await writeToBuildLog(buildLogFile, '\n=== code-server setup completed ===\n');
    installLogger.info('code-server setup completed');
    
    // Additional wait for code-server to fully start
    installLogger.debug('Giving code-server additional time to initialize');
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Get updated container info after network changes and code-server installation
    containerInfo = await containerObj.inspect();
    
    buildLogger.info({ containerName: workspaceName, networkName }, 'Container ready');
    
    // Update nginx configuration
    await updateNginxConfig(username, workspaceName, containerInfo.Id);
    
    buildLogger.info('Workspace build completed successfully');
    
    // Determine devcontainer build status
    let devcontainerBuildStatus;
    if (!hasDevcontainer) {
      devcontainerBuildStatus = 'no_devcontainer';
    } else if (retryWithDefault) {
      devcontainerBuildStatus = 'failed';
    } else {
      devcontainerBuildStatus = 'success';
    }
    
    return {
      containerId: containerInfo.Id,
      name: workspaceName,
      url: `/${username}/workspaces/${workspaceName}`,
      status: 'running',
      devcontainerBuildStatus
    };
  } catch (error) {
    buildLogger.error({ error: error.message, stack: error.stack }, 'Error in buildWithDevcontainerCLI');
    
    // Check if this is a network connection error that can be ignored
    const isNetworkConflictError = error.message && (
      error.message.includes('conflicts with existing route') ||
      error.message.includes('already exists in network') ||
      (error.message.includes('failed to add interface') && error.message.includes('sandbox'))
    );
    
    if (isNetworkConflictError) {
      buildLogger.warn({ error: error.message }, 'Network connection error detected, but container may be functional');
      await writeToBuildLog(buildLogFile, `\n=== WARNING: Network Connection Issue ===\nError: ${error.message}\n\nThe container was created successfully but there was an issue connecting it to the network.\nThis usually happens when the container is already on the network.\nAttempting to continue...\n`);
      
      // Try to verify the container is actually running and accessible
      try {
        const containers = await docker.listContainers({ all: true });
        const container = containers.find(c => 
          c.Labels && 
          c.Labels['workspaces.workspace'] === workspaceName &&
          c.Labels['workspaces.username'] === username
        );
        
        if (container && container.State === 'running') {
          buildLogger.info({ containerId: container.Id }, 'Container is running despite network error, continuing');
          
          await updateNginxConfig(username, workspaceName, container.Id);
          buildLogger.info({ containerName: workspaceName }, 'Container ready despite network issue');
          
          await writeToBuildLog(buildLogFile, `\n=== BUILD COMPLETED WITH WARNINGS ===\nContainer is running and accessible.\n`);
          
          // Determine devcontainer build status
          let devcontainerBuildStatus;
          if (!hasDevcontainer) {
            devcontainerBuildStatus = 'no_devcontainer';
          } else if (retryWithDefault) {
            devcontainerBuildStatus = 'failed';
          } else {
            devcontainerBuildStatus = 'success';
          }
          
          return {
            containerId: container.Id,
            name: workspaceName,
            url: `/${username}/workspaces/${workspaceName}`,
            status: 'running',
            devcontainerBuildStatus
          };
        }
      } catch (verifyError) {
        buildLogger.error({ error: verifyError.message }, 'Failed to verify container status');
      }
      
      // If we couldn't verify the container, treat it as a real error
      buildLogger.error('Could not verify container is functional, treating as build failure');
    }
    
    // Enhanced error message for common issues
    let enhancedMessage = error.message;
    let shouldRetryWithDefault = false;
    
    // Check if we should retry with default image
    // Retry if:
    // 1. We have a devcontainer.json (hasDevcontainer)
    // 2. We're not already retrying (retryWithDefault is false)
    // 3. The build failed (any non-zero exit code or other error)
    if (!retryWithDefault && hasDevcontainer) {
      shouldRetryWithDefault = true;
      
      // Enhanced error message for specific issues
      if (error.message.includes('docker inspect --type image')) {
        // Extract image name from error message
        const imageMatch = error.message.match(/docker inspect --type image (.+?)[\n\s]/);
        if (imageMatch) {
          const imageName = imageMatch[1];
          enhancedMessage = `Failed to build devcontainer. The image "${imageName}" does not exist or has an incorrect tag. Please check your .devcontainer/devcontainer.json file.\n\nOriginal error: ${error.message}`;
          buildLogger.error({ imageName }, 'Invalid or non-existent Docker image specified in devcontainer.json');
        }
      } else if (error.exitCode) {
        enhancedMessage = `Failed to build devcontainer (exit code ${error.exitCode}). Will retry with default image.\n\nOriginal error: ${error.message}`;
        buildLogger.error({ exitCode: error.exitCode }, 'devcontainer up failed with non-zero exit code');
      }
      
      buildLogger.info('Will retry with default devcontainer image');
      await writeToBuildLog(buildLogFile, `\nBuild failed. Will retry with default image...\n`);
    }
    
    await writeToBuildLog(buildLogFile, `\n=== BUILD FAILED ===\nError: ${enhancedMessage}\n${error.stack || ''}\n`);
    
    // Check if error has stderr
    if (error.stderr) {
      await writeToBuildLog(buildLogFile, `\nCommand stderr:\n${error.stderr}\n`);
    }
    if (error.stdout) {
      await writeToBuildLog(buildLogFile, `\nCommand stdout:\n${error.stdout}\n`);
    }
    
    // Retry with default image if appropriate
    if (shouldRetryWithDefault) {
      buildLogger.info('Retrying build with default devcontainer image');
      try {
        return await buildWithDevcontainerCLI(workspaceDir, username, workspaceName, envVars, hasDevcontainer, true);
      } catch (retryError) {
        buildLogger.error({ error: retryError.message }, 'Retry with default image also failed');
        await writeToBuildLog(buildLogFile, `\n=== RETRY WITH DEFAULT IMAGE ALSO FAILED ===\n`);
        // Throw the retry error
        const finalError = new Error(`Both original and fallback builds failed. Last error: ${retryError.message}`);
        finalError.originalError = error;
        finalError.retryError = retryError;
        throw finalError;
      }
    }
    
    // Throw enhanced error
    const enhancedError = new Error(enhancedMessage);
    enhancedError.originalError = error;
    throw enhancedError;
  } finally {
    // Clean up temporary devcontainer.json if created
    if (tempDevcontainerPath) {
      try {
        // If we had backed up the original, restore it
        if (originalDevcontainerBackup) {
          await fs.writeFile(tempDevcontainerPath, originalDevcontainerBackup);
          buildLogger.info('Restored original devcontainer.json');
          await writeToBuildLog(buildLogFile, '\n=== Restored original devcontainer.json ===\n');
        } else {
          // Otherwise, remove the temporary .devcontainer directory entirely
          const devcontainerDir = path.join(workspaceDir, '.devcontainer');
          await execAsync(`rm -rf "${devcontainerDir}"`);
          buildLogger.info('Removed temporary .devcontainer directory');
          await writeToBuildLog(buildLogFile, '\n=== Cleaned up temporary .devcontainer directory ===\n');
        }
      } catch (error) {
        buildLogger.warn({ error: error.message }, 'Failed to clean up devcontainer files');
        // Don't fail the build if cleanup fails
      }
    }
  }
}



async function updateNginxConfig(username, workspaceName, containerId) {
  // Use code-server container name
  const containerName = `code-server-${workspaceName}`;
  const upstreamName = `workspace_${workspaceName.replace(/-/g, '_')}`;
  
  // Create upstream configuration file (outside server block)
  const upstreamFile = path.join(NGINX_CONFIG_DIR, `workspace-${username}-${workspaceName}.upstream.conf`);
  const upstreamConfig = `
# Workspace: ${username}/${workspaceName}
upstream ${upstreamName} {
    zone upstream_dynamic 64k;
    server ${containerName}:8080 resolve max_fails=0;
}
`;
  
  await fs.writeFile(upstreamFile, upstreamConfig);
  
  // Create location configuration file (inside server block)
  const locationFile = path.join(NGINX_CONFIG_DIR, `workspace-${username}-${workspaceName}.location.conf`);
  const locationConfig = `
# Workspace: ${username}/${workspaceName}
location /${username}/workspaces/${workspaceName}/ {
    # Authentication check
    auth_request /auth/verify;
    error_page 401 = /auth/login.html;
    error_page 502 /workspace-starting.html;
    
    proxy_pass http://${upstreamName}/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 86400;
    proxy_connect_timeout 300s;
    proxy_next_upstream error timeout http_502 http_503 http_504;
    proxy_next_upstream_tries 10;
    proxy_next_upstream_timeout 300s;
}
`;
  
  await fs.writeFile(locationFile, locationConfig);
  
  // Reload nginx (non-fatal if it fails due to SSL cert issues)
  try {
    await execAsync('docker exec nginx nginx -s reload');
  } catch (error) {
    // Log the error but don't throw - SSL cert issues shouldn't block workspace creation
    logger.warn({ error: error.message }, 'Nginx reload failed (likely SSL certificate issue), but config was written');
  }
}

// Helper function to remove workspace directory with retries
async function removeWorkspaceDirectory(workspaceDir, logger) {
  const maxRetries = 3;
  const retryDelay = 2000; // 2 seconds
  
  logger.info({ workspaceDir, maxRetries }, 'Starting workspace directory removal with retries');
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logger.debug({ workspaceDir, attempt, maxRetries }, 'Attempting to remove workspace directory');
      
      // Try direct removal first - works if permissions allow
      try {
        logger.debug({ workspaceDir }, 'Trying direct rm -rf');
        await execAsync(`rm -rf "${workspaceDir}"`);
        logger.info({ workspaceDir }, 'Workspace directory removed successfully via direct rm');
        return; // Success
      } catch (directError) {
        logger.debug({ error: directError.message }, 'Direct removal failed, trying with docker run');
        
        // Fallback to docker run method with a delay to avoid mount issues
        logger.debug('Waiting 1 second before docker run fallback');
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const deleteCmd = `docker run --rm -v "${workspaceDir}":"${workspaceDir}" ubuntu:22.04 sh -c "rm -rf ${workspaceDir}"`;
        logger.debug({ command: deleteCmd }, 'Executing docker run command');
        await execAsync(deleteCmd);
        logger.info({ workspaceDir }, 'Workspace directory removed successfully via docker run');
        return; // Success
      }
    } catch (error) {
      logger.warn({ workspaceDir, attempt, maxRetries, error: error.message }, `Failed to remove workspace directory (attempt ${attempt}/${maxRetries})`);
      
      if (attempt < maxRetries) {
        logger.info({ retryDelay }, 'Waiting before retry');
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      } else {
        logger.error({ workspaceDir, error: error.message }, 'Failed to remove workspace directory after all retries');
        // Don't throw - make it non-fatal but log the error
      }
    }
  }
  
  logger.warn({ workspaceDir }, 'Workspace directory removal completed with errors (directory may still exist)');
}

async function deleteWorkspace(containerId) {
  const containerLogger = logger.child({ containerId, action: 'delete-workspace' });
  
  let username = null;
  let workspaceName = null;
  
  try {
    const container = docker.getContainer(containerId);
    
    // Get container info before removal (to get labels)
    let containerInfo;
    try {
      containerInfo = await container.inspect();
      username = containerInfo.Config.Labels['workspaces.username'];
      workspaceName = containerInfo.Config.Labels['workspaces.workspace'];
      
      containerLogger.info({ username, workspaceName }, 'Container found, proceeding with deletion');
      
      const wsLogger = createWorkspaceLogger(username, workspaceName);
      
      // Stop container
      try {
        containerLogger.info('Stopping container');
        await container.stop();
      } catch (error) {
        containerLogger.debug('Container already stopped');
      }
      
      // Remove container
      containerLogger.info('Removing container');
      try {
        await container.remove();
        containerLogger.debug('Container removed successfully');
        
        // Wait a moment for the mount to be fully released
        await new Promise(resolve => setTimeout(resolve, 1000));
      } catch (removeError) {
        containerLogger.error({ removeError: removeError.message }, 'Error removing container, but continuing with cleanup');
        // Continue with cleanup even if remove fails
      }
    } catch (error) {
      // Container does not exist (e.g., build failed)
      containerLogger.warn({ error: error.message }, 'Container not found - it may have failed to build');
      containerLogger.info('deleteWorkspace cannot clean up files without username/workspaceName from container');
      // Throw error so server.js can call cleanupWorkspaceFiles with proper username/workspaceName
      throw error;
    }
    
    // Remove nginx config (only if we have username and workspaceName)
    if (username && workspaceName) {
      const upstreamFile = path.join(NGINX_CONFIG_DIR, `workspace-${username}-${workspaceName}.upstream.conf`);
      const locationFile = path.join(NGINX_CONFIG_DIR, `workspace-${username}-${workspaceName}.location.conf`);
      containerLogger.debug({ upstreamFile, locationFile }, 'Removing nginx config files');
      await fs.unlink(upstreamFile).catch(() => {});
      await fs.unlink(locationFile).catch(() => {});
      
            // Reload nginx
      await execAsync('docker exec nginx nginx -s reload');
      containerLogger.debug('Nginx reloaded');
      
      // Wait a bit more to ensure mount is released
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Remove workspace directory
      const workspaceDir = path.join(WORKSPACES_BASE_DIR, workspaceName);
      containerLogger.info({ workspaceDir }, 'About to remove workspace directory');
      try {
        await removeWorkspaceDirectory(workspaceDir, containerLogger);
      } catch (error) {
        const wsLogger = createWorkspaceLogger(username, workspaceName);
        wsLogger.warn({ workspaceDir, error: error.message }, 'Failed to remove workspace directory after retries');
        // Don't throw - we want to continue even if directory removal fails
      }
    }
    
    containerLogger.info('Workspace deleted successfully');
  } catch (error) {
    containerLogger.error({ error: error.message, stack: error.stack }, 'Error deleting workspace');
    throw error;
  }
}

async function startWorkspace(containerId) {
  const startLogger = logger.child({ containerId, action: 'start-workspace' });
  startLogger.info('Starting workspace container');
  
  const container = docker.getContainer(containerId);
  await container.start();
  
  // Wait for container to be fully started
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Get UID 1000 user name
  const containerInfo = await container.inspect();
  const username = containerInfo.Config.Labels['workspaces.username'];
  const workspaceName = containerInfo.Config.Labels['workspaces.workspace'];
  const uid1000Logger = createContainerLogger(username, workspaceName, containerId, 'ensure-uid1000');
  
  let uid1000User;
  try {
    uid1000User = await ensureUID1000User(container, uid1000Logger);
    startLogger.info({ user: uid1000User }, 'UID 1000 user identified');
  } catch (error) {
    startLogger.error({ error: error.message }, 'Failed to ensure UID 1000 user, using root');
    uid1000User = 'root';
  }
  
  // Start code-server as UID 1000 user
  startLogger.info({ user: uid1000User }, 'Starting code-server as UID 1000 user');
  const startScript = `
    set -e
    echo "Starting code-server on port 8080 as user ${uid1000User}..."
    nohup code-server --bind-addr 0.0.0.0:8080 --auth none /workspaces > /tmp/code-server.log 2>&1 &
    CODE_SERVER_PID=$!
    echo "code-server started with PID: $CODE_SERVER_PID"
    
    # Wait for code-server to be ready
    echo "Waiting for code-server to start..."
    i=1
    while [ $i -le 30 ]; do
      if nc -z localhost 8080 2>/dev/null || netstat -tuln 2>/dev/null | grep -q ':8080 '; then
        echo "code-server is ready on port 8080!"
        exit 0
      fi
      echo "Waiting... ($i/30)"
      sleep 1
      i=$((i + 1))
    done
    
    echo "WARNING: code-server may not be ready yet"
    exit 0
  `;
  
  const execStart = await container.exec({
    Cmd: ['/bin/sh', '-c', startScript],
    AttachStdout: true,
    AttachStderr: true,
    User: uid1000User
  });
  
  const stream = await execStart.start({});
  
  // Collect and log output
  await new Promise((resolve, reject) => {
    stream.on('end', resolve);
    stream.on('error', reject);
    stream.on('data', (chunk) => {
      const text = chunk.toString();
      if (text.includes('ready') || text.includes('ERROR')) {
        startLogger.info({ message: text.trim() }, 'code-server start progress');
      } else {
        startLogger.debug({ message: text.trim() }, 'code-server start output');
      }
    });
  });
  
  startLogger.info('Workspace started successfully');
}

async function stopWorkspace(containerId) {
  const stopLogger = logger.child({ containerId, action: 'stop-workspace' });
  stopLogger.info('Stopping workspace');
  
  const container = docker.getContainer(containerId);
  
  // Check container state first
  try {
    stopLogger.debug('Inspecting container state');
    const containerInfo = await container.inspect();
    if (!containerInfo.State.Running) {
      stopLogger.warn({ status: containerInfo.State.Status }, 'Container is already stopped');
      return;
    }
  } catch (error) {
    stopLogger.error({ error: error.message }, 'Failed to inspect container');
    throw error;
  }
  
  // Gracefully stop code-server before stopping container
  try {
    stopLogger.debug('Stopping code-server gracefully');
    const stopScript = `pkill -f 'code-server' || true`;
    const execStop = await container.exec({
      Cmd: ['/bin/sh', '-c', stopScript],
      AttachStdout: true,
      AttachStderr: true
    });
    await execStop.start({});
  } catch (error) {
    stopLogger.debug({ error: error.message }, 'Error stopping code-server (continuing)');
  }
  
  await container.stop();
  stopLogger.info('Workspace stopped successfully');
}

function generatePassword() {
  return Math.random().toString(36).slice(-12);
}

// Build workspace (for rebuild - workspace directory already exists)
async function buildWorkspace(username, workspaceName, envVars = {}, workspaceId = null) {
  const buildLogger = createActionLogger(username, workspaceName, 'rebuild-workspace');
  buildLogger.info('Rebuilding workspace');
  
  const workspaceDir = path.join(WORKSPACES_BASE_DIR, workspaceName);
  
  // Check if workspace directory exists
  try {
    await fs.access(workspaceDir);
  } catch (error) {
    buildLogger.error({ workspaceDir }, 'Workspace directory does not exist');
    throw new Error('Workspace directory not found');
  }
  
  // Check for .devcontainer/devcontainer.json
  const devcontainerPath = path.join(workspaceDir, '.devcontainer', 'devcontainer.json');
  let hasDevcontainer = false;
  
  try {
    await fs.access(devcontainerPath);
    hasDevcontainer = true;
    buildLogger.info('Found devcontainer.json');
  } catch (error) {
    buildLogger.info('No devcontainer.json found, will use default image');
  }
  
  // Build devcontainer
  const result = await buildWithDevcontainerCLI(workspaceDir, username, workspaceName, envVars, hasDevcontainer);
  
  buildLogger.info({ containerId: result.containerId, containerIP: result.containerIP }, 'Workspace rebuilt successfully');
  
  return result;
}

// Helper function to clean up workspace files when container doesn't exist
async function cleanupWorkspaceFiles(username, workspaceName) {
  const cleanupLogger = logger.child({ username, workspaceName, action: 'cleanup-workspace-files' });
  
  try {
    cleanupLogger.info('Starting workspace files cleanup');
    
    // Remove nginx config files
    const upstreamFile = path.join(NGINX_CONFIG_DIR, `workspace-${username}-${workspaceName}.upstream.conf`);
    const locationFile = path.join(NGINX_CONFIG_DIR, `workspace-${username}-${workspaceName}.location.conf`);
    cleanupLogger.debug({ upstreamFile, locationFile }, 'Removing nginx config files');
    await fs.unlink(upstreamFile).catch(() => {});
    await fs.unlink(locationFile).catch(() => {});
    
    // Reload nginx
    try {
      await execAsync('docker exec workspaces-nginx nginx -s reload');
      cleanupLogger.debug('Nginx reloaded');
    } catch (error) {
      cleanupLogger.warn({ error: error.message }, 'Failed to reload nginx');
    }
    
    // Wait a moment to ensure any mounts are released
    cleanupLogger.info('Waiting 2 seconds for mounts to be released');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Remove workspace directory
    const workspaceDir = path.join(WORKSPACES_BASE_DIR, workspaceName);
    cleanupLogger.info({ workspaceDir }, 'About to remove workspace directory');
    try {
      await removeWorkspaceDirectory(workspaceDir, cleanupLogger);
      cleanupLogger.info({ workspaceDir }, 'Workspace directory removed successfully');
    } catch (error) {
      cleanupLogger.warn({ workspaceDir, error: error.message }, 'Failed to remove workspace directory after retries');
      // Don't throw - we want to continue even if directory removal fails
    }
    
    cleanupLogger.info('Workspace files cleaned up successfully');
  } catch (error) {
    cleanupLogger.error({ error: error.message, stack: error.stack }, 'Error cleaning up workspace files');
    throw error;
  }
}

// Helper function to get build log file path
function getBuildLogPath(workspaceName) {
  return path.join(BUILD_LOGS_BASE_DIR, `${workspaceName}.log`);
}

// Helper function to write to build log
async function writeToBuildLog(logFile, message) {
  try {
    await fs.appendFile(logFile, message + '\n');
  } catch (error) {
    logger.error({ error: error.message, logFile }, 'Failed to write to build log');
  }
}

// Helper function to read build log
async function readBuildLog(workspaceName) {
  const buildLogPath = getBuildLogPath(workspaceName);
  try {
    const content = await fs.readFile(buildLogPath, 'utf8');
    return content;
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error('Build log not found');
    }
    throw error;
  }
}

// Helper function to ensure UID 1000 user exists in container
async function ensureUID1000User(containerObj, containerLogger) {
  try {
    containerLogger.info('Checking for UID 1000 user in container');
    
    // Get current user running in the container
    const idExec = await containerObj.exec({
      Cmd: ['id', '-un'],
      AttachStdout: true,
      AttachStderr: true
    });
    
    const idStream = await idExec.start({ hijack: true, stdin: false });
    let currentUser = '';
    
    // Use demuxStream to handle Docker's stream format
    const stdout = [];
    const stderr = [];
    
    docker.modem.demuxStream(idStream, 
      { write: (chunk) => stdout.push(chunk) },
      { write: (chunk) => stderr.push(chunk) }
    );
    
    await new Promise((resolve) => idStream.on('end', resolve));
    currentUser = Buffer.concat(stdout).toString('utf8').trim();
    
    containerLogger.info({ currentUser }, 'Current container user');
    
    if (currentUser === 'root') {
      // Check if UID 1000 user exists
      const getentExec = await containerObj.exec({
        Cmd: ['getent', 'passwd', '1000'],
        AttachStdout: true,
        AttachStderr: true
      });
      
      const getentStream = await getentExec.start({ hijack: true, stdin: false });
      
      // Use demuxStream to handle Docker's stream format
      const getentStdout = [];
      const getentStderr = [];
      
      docker.modem.demuxStream(getentStream, 
        { write: (chunk) => getentStdout.push(chunk) },
        { write: (chunk) => getentStderr.push(chunk) }
      );
      
      await new Promise((resolve) => getentStream.on('end', resolve));
      const getentOutput = Buffer.concat(getentStdout).toString('utf8').trim();
      
      if (!getentOutput) {
        // UID 1000 user doesn't exist, create it
        containerLogger.info('Creating UID 1000 user (codespace)');
        
        const useraddExec = await containerObj.exec({
          Cmd: ['useradd', '-u', '1000', '-m', '-s', '/bin/bash', 'codespace'],
          AttachStdout: true,
          AttachStderr: true,
          User: 'root'
        });
        
        await useraddExec.start({});
        containerLogger.info('Created UID 1000 user: codespace');
        return 'codespace';
      } else {
        // UID 1000 user exists, extract username
        const existingUser = getentOutput.split(':')[0].trim();
        containerLogger.info({ existingUser }, 'UID 1000 user already exists');
        return existingUser;
      }
    } else {
      // Current user is not root, change their UID to 1000
      containerLogger.info({ currentUser }, 'Changing user UID to 1000');
      
      const usermodExec = await containerObj.exec({
        Cmd: ['usermod', '-u', '1000', '-o', currentUser],
        AttachStdout: true,
        AttachStderr: true,
        User: 'root'
      });
      
      await usermodExec.start({});
      
      // Also try to change GID if possible
      try {
        const groupmodExec = await containerObj.exec({
          Cmd: ['groupmod', '-g', '1000', '-o', currentUser],
          AttachStdout: true,
          AttachStderr: true,
          User: 'root'
        });
        
        await groupmodExec.start({});
      } catch (groupError) {
        containerLogger.warn({ error: groupError.message }, 'Failed to change group GID, continuing');
      }
      
      containerLogger.info({ currentUser }, 'Changed user UID to 1000');
      return currentUser;
    }
  } catch (error) {
    containerLogger.error({ error: error.message }, 'Error ensuring UID 1000 user');
    throw error;
  }
}

module.exports = {
  createWorkspace,
  buildWorkspace,
  deleteWorkspace,
  startWorkspace,
  stopWorkspace,
  getBuildLogPath,
  readBuildLog,
  cleanupWorkspaceFiles
};
