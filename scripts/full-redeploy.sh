#!/bin/bash
set -e

# Full redeploy script for Pseudo CodeSpaces
# This script performs a complete rebuild of the infrastructure

echo "========================================="
echo "Full Redeploy - Pseudo CodeSpaces"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Get old server IP before destroying
echo -e "${YELLOW}Step 1: Getting old server IP (if exists)${NC}"
cd terraform

# Try to get server IP from terraform output
OLD_SERVER_IP=$(terraform output -raw server_ip 2>/dev/null || echo "")

if [ -n "$OLD_SERVER_IP" ]; then
    echo "Old server IP: ${OLD_SERVER_IP}"
fi

# Step 2: Destroy existing infrastructure
echo -e "${YELLOW}Step 2: Destroying existing infrastructure${NC}"
terraform destroy -auto-approve || {
    echo -e "${RED}Warning: Destroy failed or no infrastructure to destroy${NC}"
}

# Wait for resources to be fully deleted
echo "Waiting 30 seconds for resources to be fully deleted..."
sleep 30

# Remove SSH known host entry for old server
if [ -n "$OLD_SERVER_IP" ]; then
    echo -e "${YELLOW}Removing SSH known host entry for ${OLD_SERVER_IP}...${NC}"
    ssh-keygen -R "$OLD_SERVER_IP" 2>/dev/null || echo "No SSH host key found for ${OLD_SERVER_IP}"
fi

# Step 3: Clean up Terraform state
echo -e "${YELLOW}Step 3: Cleaning up Terraform state${NC}"
rm -f terraform.tfstate*
rm -rf .terraform

# Step 4: Re-initialize Terraform
echo -e "${YELLOW}Step 4: Re-initializing Terraform${NC}"
terraform init

# Step 5: Validate configuration
echo -e "${YELLOW}Step 5: Validating Terraform configuration${NC}"
terraform validate

# Step 6: Plan
echo -e "${YELLOW}Step 6: Planning infrastructure${NC}"
terraform plan

# Step 7: Apply
echo -e "${YELLOW}Step 7: Applying infrastructure (this may take 5-10 minutes)${NC}"
terraform apply -auto-approve

# Get server IP
SERVER_IP=$(terraform output -raw server_ip)
echo -e "${GREEN}Server IP: ${SERVER_IP}${NC}"
echo ""

# Step 8: Wait for server to boot (SSH check)
echo -e "${YELLOW}Step 8: Waiting for server to boot${NC}"
echo "Checking connectivity with SSH (max 10 minutes)..."
echo ""

MAX_ATTEMPTS=120  # 10 minutes (5 second intervals)
ATTEMPT=0
SERVER_UP=false

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    ATTEMPT=$((ATTEMPT + 1))
    ELAPSED=$((ATTEMPT * 5))
    
    # Progress display
    printf "\r   Elapsed: %d seconds / 600 seconds - SSH attempt %d/%d..." $ELAPSED $ATTEMPT $MAX_ATTEMPTS
    
    # SSH test (5 second timeout)
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes ubuntu@"$SERVER_IP" exit 2>/dev/null; then
        echo ""
        echo -e "${GREEN}✓ Server is up! (after ${ELAPSED} seconds)${NC}"
        SERVER_UP=true
        break
    fi
    
    sleep 5
done

echo ""

if [ "$SERVER_UP" = false ]; then
    echo -e "${RED}✗ Timeout: Server not responding after 10 minutes${NC}"
    echo ""
    echo "Please check the Web Console:"
    echo "  https://secure.sakura.ad.jp/cloud/"
    echo ""
    echo "Possible causes:"
    echo "  - Server still booting (cloud-init takes time)"
    echo "  - SSH key authentication issue"
    echo "  - Network configuration issue"
    echo ""
    echo "Try logging in via Web Console:"
    echo "  Username: ubuntu"
    echo "  Password: TempPassword123!"
    echo ""
    echo "Then check:"
    echo "  - sudo cloud-init status"
    echo "  - ip a show ens3"
    echo "  - sudo systemctl status sshd"
else
    # Wait a bit more for cloud-init to complete
    echo "⏳ Waiting for cloud-init to complete (30 seconds)..."
    sleep 30
fi

echo ""

# Step 9: Test connectivity
echo -e "${YELLOW}Step 9: Testing connectivity${NC}"
echo "Testing SSH connection..."
if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no ubuntu@"$SERVER_IP" "echo 'SSH connection successful'" 2>&1 | grep -q "SSH connection successful"; then
    echo -e "${GREEN}✓ SSH connection successful${NC}"
    
    # Check cloud-init status
    echo ""
    echo "Checking cloud-init status..."
    ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no ubuntu@"$SERVER_IP" "sudo cloud-init status" 2>&1 || echo -e "${YELLOW}⚠ Could not check cloud-init status${NC}"
else
    echo -e "${YELLOW}⚠ SSH connection failed or cloud-init still running${NC}"
    echo ""
    echo "You may need to:"
    echo "1. Wait a few more minutes for cloud-init to complete"
    echo "2. Try connecting via Web Console:"
    echo "   Username: ubuntu"
    echo "   Password: TempPassword123!"
    echo "3. Check cloud-init logs:"
    echo "   sudo cloud-init status"
    echo "   sudo cat /var/log/cloud-init-output.log"
fi

# Step 10: Update Ansible inventory
echo -e "${YELLOW}Step 10: Updating Ansible inventory${NC}"
cd ../ansible
cat > inventory.ini << EOF
[pseudo_codespaces]
${SERVER_IP} ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/id_rsa

[pseudo_codespaces:vars]
ansible_python_interpreter=/usr/bin/python3
EOF

echo -e "${GREEN}Inventory updated${NC}"

# Step 11: Summary
echo ""
echo "========================================="
echo -e "${GREEN}Redeploy Complete!${NC}"
echo "========================================="
echo ""
echo "Server IP: ${SERVER_IP}"
echo ""
echo "Next steps:"
echo "1. Test SSH connection: ssh ubuntu@${SERVER_IP}"
echo "2. Or login via Web Console:"
echo "   - Go to Sakura Cloud Control Panel"
echo "   - Open VNC Console"
echo "   - Username: ubuntu"
echo "   - Password: TempPassword123!"
echo "3. Once SSH works, run Ansible:"
echo "   cd ansible"
echo "   ANSIBLE_CONFIG=ansible.cfg ansible-playbook -i inventory.ini playbook.yml"
echo ""
echo -e "${YELLOW}Important: Change the password after first login!${NC}"
echo "   sudo passwd ubuntu"
echo ""
