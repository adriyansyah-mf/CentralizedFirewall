# Firewall Manager API Project

## Installation

Follow these steps to set up and run the API project:

### 1. Clone the Repository
```bash
git clone https://github.com/adriyansyah-mf/CentralizedFirewall
cd CentralizedFirewall
```

### 2. Edit the `.env` File
Update the environment variables in `.env` according to your configuration.

```bash
nano .env
```

### 3. Start the API with Docker Compose
```bash
docker compose up -d
```

This will start the API in detached mode.

### 4. Verify the API is Running
Check if the containers are up:
```bash
docker ps
```


---

## Additional Commands

### Stop the API
```bash
docker compose down
```

### Restart the API
```bash
docker compose restart
```

Let me know if you need any modifications! 🚀

### How to setup for the first time and connect to firewall client
1. Install Firewall Agent on your node server
2. Run the agent with the following command
```bash
sudo dpkg -i firewall-client_deb.deb
```
3. Create a New Group on the Firewall Manager
4. Create New API Key on the Firewall Manager
5. Edit the configuration file on the node server
```bash
nano /usr/local/bin/config.ini
```
6. Add the following configuration
```bash
[settings]
api_url = API-URL
api_key = API-KEY
hostname = Node Hostname (make it unique and same as the hostname on the SIEM) 
```

7. Restart the firewall agent
```bash
systemctl daemon-reload
systemctl start firewall-agent
```

8. Check the status of the firewall agent
```bash
systemctl status firewall-agent
```

9. You will see the connected node on the Firewall Manager

### Default Credential
```bash
Username: admin
Password: admin
```

You can change the default credential on the setting page

### How to Integration with SIEM
1. Install the SIEM on your server
2. Configure the SIEM to send the log to the Firewall Manager (You can do this via SOAR or SIEM configuration)
    The request should be POST with the following format
3. The format of the log should be like this
```bash
curl -X 'POST' \
  'http://api-server:8000/general/add-ip?ip=123.1.1.99&hostname=test&apikey=apikey&comment=log' \
  -H 'accept: application/json' \
  -d ''
```
You can see the swagger documentation on the following link
```bash
http://api-server:8000/docs
```

### The .env detail configuration
```bash
DB=changeme
JWT_SECRET=changeme
PASSWORD_SALT=changme
PASSWORD_TOKEN_KEY=changme
OPENCTI_URL=changme
OPENCTI_TOKEN=changme
```

## Sponsor This Project 💖  

If you find this project helpful, consider supporting me through GitHub Sponsors:  

[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub-%23ea4aaa?style=for-the-badge&logo=github)](https://github.com/sponsors/adriyansyah-mf)