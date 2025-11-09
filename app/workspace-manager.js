const Docker = require('dockerode');
const simpleGit = require('simple-git');
const fs = require('fs').promises;
const path = require('path');
const yaml = require('js-yaml');
const { exec } = require('child_process');
const { promisify } = require('util');
const { 
  logger, 
  createWorkspaceLogger, 
  createActionLogger,
  createContainerLogger 
} = require('./logger');

const execAsync = promisify(exec);
const docker = new Docker();

const WORKSPACES_BASE_DIR = '/home';
const NGINX_CONFIG_DIR = '/opt/nginx-config';
const BUILD_LOGS_BASE_DIR = '/home';

async function createWorkspace(username, workspaceName, repoUrl, envVars = {}, workspaceId = null) {
  const wsLogger = createWorkspaceLogger(username, workspaceName);
  if (workspaceId) {
    wsLogger.info({ repoUrl, workspaceId }, 'Creating workspace');
  } else {
    wsLogger.info({ repoUrl }, 'Creating workspace');
  }
  
  const workspaceDir = path.join(WORKSPACES_BASE_DIR, username, 'workspaces', workspaceName);
  
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
  
  // Clone repository
  const cloneLogger = createActionLogger(username, workspaceName, 'clone-repository');
  cloneLogger.info({ repoUrl }, 'Cloning repository');
  const git = simpleGit();
  await git.clone(repoUrl, workspaceDir);
  cloneLogger.info('Repository cloned successfully');
  
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
    buildLogger.info('Retrying build with default devcontainer image after previous failure');
  } else {
    buildLogger.info('Building and starting devcontainer using @devcontainers/cli');
  }
  
  const containerName = `workspace-${username}-${workspaceName}`;
  const networkName = 'pseudo-codespaces_pseudo-codespaces';
  
  // Prepare build log
  const buildLogDir = path.join(BUILD_LOGS_BASE_DIR, username, 'buildlogs');
  await fs.mkdir(buildLogDir, { recursive: true });
  const buildLogFile = getBuildLogPath(username, workspaceName);
  
  if (retryWithDefault) {
    await writeToBuildLog(buildLogFile, `\n\n${'='.repeat(80)}\n`);
    await writeToBuildLog(buildLogFile, `RETRYING WITH DEFAULT IMAGE\n`);
    await writeToBuildLog(buildLogFile, `${'='.repeat(80)}\n\n`);
  } else {
    await fs.writeFile(buildLogFile, `Build log for ${workspaceName}\nStarted at: ${new Date().toISOString()}\n\n`);
  }
  
  // Build devcontainer up command
  let devcontainerCmd = `devcontainer up --workspace-folder "${workspaceDir}" --id-label pseudo-codespaces.workspace=${workspaceName} --id-label pseudo-codespaces.username=${username}`;
  
  // If no devcontainer.json, create a temporary one with default image
  // OR if retrying after failure, replace existing devcontainer.json with default
  let tempDevcontainerCreated = false;
  let originalDevcontainerBackup = null;
  
  if (!hasDevcontainer || retryWithDefault) {
    const defaultImage = 'mcr.microsoft.com/devcontainers/universal:2-linux';
    buildLogger.info({ defaultImage }, retryWithDefault ? 'Using default image as fallback' : 'Using default image');
    await writeToBuildLog(buildLogFile, `Using default image: ${defaultImage}\n`);
    
    // Create .devcontainer directory and devcontainer.json
    const devcontainerDir = path.join(workspaceDir, '.devcontainer');
    const devcontainerPath = path.join(devcontainerDir, 'devcontainer.json');
    
    // Backup original devcontainer.json if retrying
    if (retryWithDefault && hasDevcontainer) {
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
        name: workspaceName,
        image: defaultImage,
        
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
    const { stdout, stderr } = await execAsync(devcontainerCmd, {
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer for build output
    });
    
    // Write output to log file
    await writeToBuildLog(buildLogFile, stdout);
    if (stderr) {
      await writeToBuildLog(buildLogFile, `\n=== stderr ===\n${stderr}`);
    }
    
    // Parse the output to get container ID
    // devcontainer up outputs JSON with container info
    const lines = stdout.split('\n');
    let containerIdFromCLI = null;
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
    
    // Get the container
    let containerId = containerIdFromCLI;
    if (!containerId) {
      buildLogger.debug('Container ID not found in CLI output, searching by label');
      // Fallback: search by label
      const containers = await docker.listContainers({ all: true });
      const container = containers.find(c => 
        c.Labels && 
        c.Labels['pseudo-codespaces.workspace'] === workspaceName &&
        c.Labels['pseudo-codespaces.username'] === username
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
    
    // Connect container to our Docker network if not already connected
    const networkName = 'pseudo-codespaces_pseudo-codespaces';
    let networks = containerInfo.NetworkSettings.Networks;
    
    if (!networks[networkName]) {
      containerLogger.info({ networkName }, 'Connecting container to network');
      try {
        const network = docker.getNetwork(networkName);
        await network.connect({
          Container: containerId
        });
        containerLogger.info({ networkName }, 'Container connected to network');
      } catch (error) {
        // Check if error is about already being connected or IP conflict
        if (error.message.includes('already exists') || error.message.includes('conflicts with existing route')) {
          containerLogger.warn({ networkName, error: error.message }, 'Network connection issue (container may already be on network), continuing');
        } else {
          containerLogger.error({ networkName, error: error.message }, 'Failed to connect to network');
          throw error;
        }
      }
    } else {
      containerLogger.debug({ networkName }, 'Container already connected to network');
    }
    
    // Refresh container info after network connection to get updated network settings
    containerInfo = await containerObj.inspect();
    networks = containerInfo.NetworkSettings.Networks;
    
    // Disconnect from default bridge network to avoid routing conflicts
    // This must be done AFTER connecting to our network and refreshing container info
    if (networks['bridge']) {
      containerLogger.info('Disconnecting from default bridge network');
      try {
        const bridgeNetwork = docker.getNetwork('bridge');
        await bridgeNetwork.disconnect({
          Container: containerId,
          Force: false
        });
        containerLogger.info('Disconnected from bridge network');
        
        // Refresh container info again after disconnection
        containerInfo = await containerObj.inspect();
        networks = containerInfo.NetworkSettings.Networks;
        
        // Verify bridge is actually disconnected
        if (!networks['bridge']) {
          containerLogger.info('Verified: bridge network disconnected successfully');
          
          // Restart container to ensure network interfaces are properly configured
          // This is necessary because disconnecting from bridge may leave the container
          // without a properly configured eth0 interface for the new network
          containerLogger.info('Restarting container to refresh network interfaces');
          await containerObj.restart();
          containerLogger.info('Container restarted successfully');
          
          // Wait a moment for network to stabilize
          await new Promise(resolve => setTimeout(resolve, 2000));
          
          // Refresh container info after restart
          containerInfo = await containerObj.inspect();
          containerLogger.info('Container network interfaces refreshed after restart');
        } else {
          containerLogger.warn('Warning: bridge network still appears in container networks');
        }
      } catch (bridgeError) {
        // Non-fatal - log and continue
        containerLogger.warn({ error: bridgeError.message }, 'Could not disconnect from bridge network, continuing anyway');
      }
    } else {
      containerLogger.debug('Container is not on bridge network, no disconnection needed');
    }
    
    // Install and start code-server in the devcontainer
    const installLogger = createActionLogger(username, workspaceName, 'setup-code-server');
    installLogger.info('Installing code-server in devcontainer');
    await writeToBuildLog(buildLogFile, '\n=== Installing code-server ===\n');
    
    const installScript = `
      set -e
      echo "Starting code-server installation..."
      if ! command -v code-server &> /dev/null; then
        echo "code-server not found, installing..."
        curl -fsSL https://code-server.dev/install.sh | sh
        echo "code-server installed successfully"
      else
        echo "code-server already installed"
      fi
      
      # Start code-server in the background
      echo "Starting code-server on port 8080..."
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
    
    const execInstall = await containerObj.exec({
      Cmd: ['/bin/sh', '-c', installScript],
      AttachStdout: true,
      AttachStderr: true
    });
    
    const stream = await execInstall.start({});
    
    // Collect and log output
    let output = '';
    await new Promise((resolve, reject) => {
      stream.on('end', resolve);
      stream.on('error', reject);
      stream.on('data', (chunk) => {
        const text = chunk.toString();
        output += text;
        // Write to build log file
        writeToBuildLog(buildLogFile, text).catch(err => 
          installLogger.error({ error: err.message }, 'Failed to write to build log')
        );
        // Only log important messages at info level
        if (text.includes('ready') || text.includes('ERROR') || text.includes('installed')) {
          installLogger.info({ message: text.trim() }, 'code-server setup progress');
        } else {
          installLogger.debug({ message: text.trim() }, 'code-server setup output');
        }
      });
    });
    
    await writeToBuildLog(buildLogFile, '\n=== code-server installation completed ===\n');
    installLogger.info('code-server installation completed');
    
    // Additional wait for code-server to fully start
    installLogger.debug('Giving code-server additional time to initialize');
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Get updated container info after network changes and code-server installation
    // This ensures we get the correct IP from the pseudo-codespaces network
    containerInfo = await containerObj.inspect();
    const containerIP = getContainerIP(containerInfo);
    const containerPort = 8080;
    
    buildLogger.info({ containerIP, containerPort, networkName }, 'Container ready');
    
    // Update nginx configuration
    await updateNginxConfig(username, workspaceName, containerInfo.Id, containerIP, containerPort);
    
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
          c.Labels['pseudo-codespaces.workspace'] === workspaceName &&
          c.Labels['pseudo-codespaces.username'] === username
        );
        
        if (container && container.State === 'running') {
          buildLogger.info({ containerId: container.Id }, 'Container is running despite network error, continuing');
          const containerObj = docker.getContainer(container.Id);
          const containerInfo = await containerObj.inspect();
          
          // Try to get container IP
          let containerIP = null;
          try {
            containerIP = getContainerIP(containerInfo);
          } catch (ipError) {
            buildLogger.warn({ error: ipError.message }, 'Could not determine container IP from our network, trying all networks');
            // Try to get IP from any network
            const networks = containerInfo.NetworkSettings.Networks;
            const networkKeys = Object.keys(networks);
            if (networkKeys.length > 0) {
              containerIP = networks[networkKeys[0]].IPAddress;
              buildLogger.info({ containerIP, network: networkKeys[0] }, 'Using IP from alternate network');
            }
          }
          
          if (containerIP) {
            const containerPort = 8080;
            await updateNginxConfig(username, workspaceName, container.Id, containerIP, containerPort);
            buildLogger.info({ containerIP, containerPort }, 'Container ready despite network issue');
            
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
    
    if (error.message.includes('docker inspect --type image')) {
      // Extract image name from error message
      const imageMatch = error.message.match(/docker inspect --type image (.+?)[\n\s]/);
      if (imageMatch) {
        const imageName = imageMatch[1];
        enhancedMessage = `Failed to build devcontainer. The image "${imageName}" does not exist or has an incorrect tag. Please check your .devcontainer/devcontainer.json file.\n\nOriginal error: ${error.message}`;
        buildLogger.error({ imageName }, 'Invalid or non-existent Docker image specified in devcontainer.json');
        
        // Retry with default image if not already retrying
        if (!retryWithDefault && hasDevcontainer) {
          shouldRetryWithDefault = true;
          buildLogger.info('Will retry with default devcontainer image');
          await writeToBuildLog(buildLogFile, `\nImage not found. Will retry with default image...\n`);
        }
      }
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
          // Otherwise, remove the temporary one
          await fs.unlink(tempDevcontainerPath);
          buildLogger.info('Removed temporary devcontainer.json');
          await writeToBuildLog(buildLogFile, '\n=== Cleaned up temporary devcontainer.json ===\n');
        }
      } catch (error) {
        buildLogger.warn({ error: error.message }, 'Failed to clean up devcontainer.json');
        // Don't fail the build if cleanup fails
      }
    }
  }
}

function getCodeServerPort(containerInfo) {
  const ports = containerInfo.NetworkSettings.Ports;
  if (ports['8080/tcp'] && ports['8080/tcp'].length > 0) {
    return ports['8080/tcp'][0].HostPort;
  }
  throw new Error('Could not determine code-server port');
}

function getContainerIP(containerInfo) {
  const networks = containerInfo.NetworkSettings.Networks;
  const networkName = 'pseudo-codespaces_pseudo-codespaces';
  
  // First priority: our custom network
  if (networks[networkName] && networks[networkName].IPAddress) {
    logger.debug({ ip: networks[networkName].IPAddress, network: networkName }, 'Using IP from pseudo-codespaces network');
    return networks[networkName].IPAddress;
  }
  
  // Second priority: any non-bridge network
  for (const [netName, netInfo] of Object.entries(networks)) {
    if (netName !== 'bridge' && netInfo.IPAddress) {
      logger.warn({ ip: netInfo.IPAddress, network: netName }, 'Using IP from non-bridge network (not pseudo-codespaces)');
      return netInfo.IPAddress;
    }
  }
  
  // Last resort: bridge network (should not happen if disconnection worked)
  if (networks['bridge'] && networks['bridge'].IPAddress) {
    logger.error({ ip: networks['bridge'].IPAddress }, 'WARNING: Using IP from bridge network - this indicates disconnection failed');
    return networks['bridge'].IPAddress;
  }
  
  throw new Error('Could not determine container IP address from any network');
}

async function updateNginxConfig(username, workspaceName, containerId, containerIP, port) {
  const configFile = path.join(NGINX_CONFIG_DIR, `workspace-${username}-${workspaceName}.conf`);
  
  const config = `
# Workspace: ${username}/${workspaceName}
location /${username}/workspaces/${workspaceName}/ {
    proxy_pass http://${containerIP}:8080/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 86400;
}
`;
  
  await fs.writeFile(configFile, config);
  
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
      username = containerInfo.Config.Labels['pseudo-codespaces.username'];
      workspaceName = containerInfo.Config.Labels['pseudo-codespaces.workspace'];
      
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
      const configFile = path.join(NGINX_CONFIG_DIR, `workspace-${username}-${workspaceName}.conf`);
      containerLogger.debug({ configFile }, 'Removing nginx config');
      await fs.unlink(configFile).catch(() => {});
      
      // Reload nginx
      await execAsync('docker exec nginx nginx -s reload');
      containerLogger.debug('Nginx reloaded');
      
      // Wait a bit more to ensure mount is released
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Remove workspace directory
      const workspaceDir = path.join(WORKSPACES_BASE_DIR, username, 'workspaces', workspaceName);
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
  
  // Start code-server
  startLogger.info('Starting code-server in workspace');
  const startScript = `
    set -e
    echo "Starting code-server on port 8080..."
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
    AttachStderr: true
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
  
  const workspaceDir = path.join(WORKSPACES_BASE_DIR, username, 'workspaces', workspaceName);
  
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
    
    // Remove nginx config
    const configFile = path.join(NGINX_CONFIG_DIR, `workspace-${username}-${workspaceName}.conf`);
    cleanupLogger.debug({ configFile }, 'Removing nginx config');
    await fs.unlink(configFile).catch(() => {});
    
    // Reload nginx
    try {
      await execAsync('docker exec nginx nginx -s reload');
      cleanupLogger.debug('Nginx reloaded');
    } catch (error) {
      cleanupLogger.warn({ error: error.message }, 'Failed to reload nginx');
    }
    
    // Wait a moment to ensure any mounts are released
    cleanupLogger.info('Waiting 2 seconds for mounts to be released');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Remove workspace directory
    const workspaceDir = path.join(WORKSPACES_BASE_DIR, username, 'workspaces', workspaceName);
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
function getBuildLogPath(username, workspaceName) {
  return path.join(BUILD_LOGS_BASE_DIR, username, 'buildlogs', `${workspaceName}.log`);
}

// Helper function to write to build log
async function writeToBuildLog(logFile, message) {
  try {
    await fs.appendFile(logFile, message + '\n');
  } catch (error) {
    logger.error({ error: error.message, logFile }, 'Failed to write to build log');
  }
}

module.exports = {
  createWorkspace,
  buildWorkspace,
  deleteWorkspace,
  startWorkspace,
  stopWorkspace,
  getBuildLogPath,
  cleanupWorkspaceFiles
};
