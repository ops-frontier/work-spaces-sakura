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

async function createWorkspace(username, workspaceName, repoUrl, envVars = {}, workspaceId = null) {
  const wsLogger = createWorkspaceLogger(username, workspaceName);
  if (workspaceId) {
    wsLogger.info({ repoUrl, workspaceId }, 'Creating workspace');
  } else {
    wsLogger.info({ repoUrl }, 'Creating workspace');
  }
  
  const workspaceDir = path.join(WORKSPACES_BASE_DIR, username, 'workspaces', workspaceName);
  
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

async function buildContainerConfig(username, workspaceName, workspaceDir, devcontainer, envVars) {
  const containerName = `workspace-${username}-${workspaceName}`;
  
  // Default configuration for code-server
  let image = 'codercom/code-server:latest';
  let env = [
    `PASSWORD=${generatePassword()}`,
    'SUDO_PASSWORD=password',
    ...Object.entries(envVars).map(([key, value]) => `${key}=${value}`)
  ];
  
  // Pull image if not exists
  console.log(`Pulling image: ${image}`);
  await pullImage(image);
  
  // Workspace path for code-server
  const workspacePath = '/home/coder/workspace';
  
  return {
    name: containerName,
    Image: image,
    Env: env,
    ExposedPorts: {
      '8080/tcp': {}
    },
    HostConfig: {
      Binds: [
        `${workspaceDir}:${workspacePath}`,
      ],
      PortBindings: {
        '8080/tcp': [{ HostPort: '0' }] // Random port
      },
      AutoRemove: false,
      RestartPolicy: {
        Name: 'unless-stopped'
      },
      NetworkMode: 'pseudo-codespaces_pseudo-codespaces'
    },
    Labels: {
      'pseudo-codespaces.username': username,
      'pseudo-codespaces.workspace': workspaceName
    }
  };
}

async function pullImage(imageName) {
  return new Promise((resolve, reject) => {
    docker.pull(imageName, (err, stream) => {
      if (err) {
        return reject(err);
      }
      
      docker.modem.followProgress(stream, (err, output) => {
        if (err) {
          return reject(err);
        }
        console.log(`Successfully pulled image: ${imageName}`);
        resolve(output);
      }, (event) => {
        // Progress logging
        if (event.status && event.progress) {
          console.log(`${event.status}: ${event.progress}`);
        }
      });
    });
  });
}

async function buildDevcontainerImage(imageName, context, dockerfilePath, buildArgs) {
  console.log(`Building devcontainer image: ${imageName}`);
  console.log(`Context: ${context}`);
  console.log(`Dockerfile: ${dockerfilePath}`);
  
  // Read Dockerfile content
  const dockerfileContent = await fs.readFile(dockerfilePath, 'utf8');
  
  // Create tarball for build context
  const tar = require('tar-fs');
  const tarStream = tar.pack(context);
  
  return new Promise((resolve, reject) => {
    docker.buildImage(tarStream, {
      t: imageName,
      dockerfile: path.basename(dockerfilePath),
      buildargs: buildArgs
    }, (err, stream) => {
      if (err) {
        return reject(err);
      }
      
      docker.modem.followProgress(stream, (err, output) => {
        if (err) {
          return reject(err);
        }
        console.log(`Successfully built devcontainer image: ${imageName}`);
        resolve(output);
      }, (event) => {
        // Progress logging
        if (event.stream) {
          console.log(event.stream.trim());
        }
      });
    });
  });
}

async function buildWithDevcontainerCLI(workspaceDir, username, workspaceName, envVars = {}, hasDevcontainer = false) {
  const buildLogger = createActionLogger(username, workspaceName, 'build-devcontainer');
  buildLogger.info('Building and starting devcontainer using @devcontainers/cli');
  
  const containerName = `workspace-${username}-${workspaceName}`;
  const networkName = 'pseudo-codespaces_pseudo-codespaces';
  
  // Build devcontainer up command
  let devcontainerCmd = `devcontainer up --workspace-folder "${workspaceDir}" --id-label pseudo-codespaces.workspace=${workspaceName} --id-label pseudo-codespaces.username=${username}`;
  
  // If no devcontainer.json, specify a default image
  if (!hasDevcontainer) {
    // Use a default devcontainer image with common tools
    // Using universal image which includes most common development tools
    const defaultImage = 'mcr.microsoft.com/devcontainers/universal:2-linux';
    buildLogger.info({ defaultImage }, 'Using default image');
    devcontainerCmd += ` --image-name ${defaultImage}`;
  }
  
  buildLogger.debug({ command: devcontainerCmd }, 'Running devcontainer CLI');
  
  try {
    const { stdout, stderr } = await execAsync(devcontainerCmd, {
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer for build output
    });
    buildLogger.debug({ stdout: stdout.substring(0, 500) }, 'Devcontainer CLI output (truncated)');
    if (stderr) {
      buildLogger.warn({ stderr }, 'Devcontainer CLI stderr');
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
    const containerInfo = await containerObj.inspect();
    
    // Check if container is running
    if (!containerInfo.State.Running) {
      containerLogger.info('Container not running, starting it');
      await containerObj.start();
    }
    
    // Connect container to our Docker network if not already connected
    const networkName = 'pseudo-codespaces_pseudo-codespaces';
    const networks = containerInfo.NetworkSettings.Networks;
    
    if (!networks[networkName]) {
      containerLogger.info({ networkName }, 'Connecting container to network');
      try {
        const network = docker.getNetwork(networkName);
        await network.connect({
          Container: containerId
        });
        containerLogger.info({ networkName }, 'Container connected to network');
      } catch (error) {
        containerLogger.error({ networkName, error: error.message }, 'Failed to connect to network');
        throw error;
      }
    } else {
      containerLogger.debug({ networkName }, 'Container already connected to network');
    }
    
    // Install and start code-server in the devcontainer
    const installLogger = createActionLogger(username, workspaceName, 'setup-code-server');
    installLogger.info('Installing code-server in devcontainer');
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
        // Only log important messages at info level
        if (text.includes('ready') || text.includes('ERROR') || text.includes('installed')) {
          installLogger.info({ message: text.trim() }, 'code-server setup progress');
        } else {
          installLogger.debug({ message: text.trim() }, 'code-server setup output');
        }
      });
    });
    
    installLogger.info('code-server installation completed');
    
    // Additional wait for code-server to fully start
    installLogger.debug('Giving code-server additional time to initialize');
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Get updated container info after network connection
    const updatedInfo = await containerObj.inspect();
    const containerIP = getContainerIP(updatedInfo);
    const containerPort = 8080;
    
    buildLogger.info({ containerIP, containerPort, networkName }, 'Container ready');
    
    // Update nginx configuration
    await updateNginxConfig(username, workspaceName, updatedInfo.Id, containerIP, containerPort);
    
    buildLogger.info('Workspace build completed successfully');
    
    return {
      containerId: updatedInfo.Id,
      name: workspaceName,
      url: `/${username}/workspaces/${workspaceName}`,
      status: 'running'
    };
  } catch (error) {
    buildLogger.error({ error: error.message, stack: error.stack }, 'Error in buildWithDevcontainerCLI');
    throw error;
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
  
  if (networks[networkName] && networks[networkName].IPAddress) {
    return networks[networkName].IPAddress;
  }
  
  // Fallback to first available network
  const networkKeys = Object.keys(networks);
  if (networkKeys.length > 0 && networks[networkKeys[0]].IPAddress) {
    return networks[networkKeys[0]].IPAddress;
  }
  
  throw new Error('Could not determine container IP address');
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
  
  // Reload nginx
  await execAsync('docker exec nginx nginx -s reload');
}

async function deleteWorkspace(containerId) {
  const containerLogger = logger.child({ containerId, action: 'delete-workspace' });
  
  try {
    const container = docker.getContainer(containerId);
    
    // Get container info before removal (to get labels)
    const containerInfo = await container.inspect();
    const username = containerInfo.Config.Labels['pseudo-codespaces.username'];
    const workspaceName = containerInfo.Config.Labels['pseudo-codespaces.workspace'];
    
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
    } catch (removeError) {
      containerLogger.error({ removeError: removeError.message }, 'Error removing container, but continuing with cleanup');
      // Continue with cleanup even if remove fails
    }
    
    // Remove nginx config
    const configFile = path.join(NGINX_CONFIG_DIR, `workspace-${username}-${workspaceName}.conf`);
    containerLogger.debug({ configFile }, 'Removing nginx config');
    await fs.unlink(configFile).catch(() => {});
    
    // Reload nginx
    await execAsync('docker exec nginx nginx -s reload');
    containerLogger.debug('Nginx reloaded');
    
    // Remove workspace directory
    const workspaceDir = path.join(WORKSPACES_BASE_DIR, username, 'workspaces', workspaceName);
    try {
      containerLogger.debug({ workspaceDir }, 'Removing workspace directory');
      // Execute deletion on host using docker run with host volume
      // This avoids permission issues with files owned by devcontainer user
      const deleteCmd = `docker run --rm -v "${workspaceDir}":"${workspaceDir}" ubuntu:22.04 sh -c "rm -rf ${workspaceDir}"`;
      await execAsync(deleteCmd);
      containerLogger.debug({ workspaceDir }, 'Workspace directory removed');
    } catch (error) {
      wsLogger.warn({ workspaceDir, error: error.message }, 'Failed to remove workspace directory');
      // Don't throw - we want to continue even if directory removal fails
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

module.exports = {
  createWorkspace,
  deleteWorkspace,
  startWorkspace,
  stopWorkspace
};
