#!/bin/bash

# Fix packages if needed
sudo dpkg --configure -a

# Remove old Docker versions
sudo apt remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
sudo apt autoremove -y

# Update repo
sudo apt update

# Install dependencies
sudo apt install -y ca-certificates curl gnupg lsb-release

# Setup Docker GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repo
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update once more and install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Show Docker version
docker --version

echo ""
echo "✅ Docker cài xong rồi!"
echo "⚠️ Lưu ý: Codespace không hỗ trợ systemctl, nên không cần check systemctl status"
echo ""
