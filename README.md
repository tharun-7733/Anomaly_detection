# NetGuard AI - Network Anomaly Detection System

A real-time network traffic monitoring and anomaly detection system. It captures live network packets, extracts traffic features, and uses an Isolation Forest Machine Learning model to identify malicious or anomalous network behavior. 

## 🏗️ Project Architecture

This project is divided into two main components:
1. **Backend (FastAPI & Scapy)**: A Python server that requires root/admin privileges to sniff raw network packets off the network interface. It uses an ML model (`isolation_forest.pkl`) to score traffic anomalies in real-time.
2. **Frontend (React & Vite)**: A modern, real-time dashboard that displays network statistics, live traffic streams, and high-severity anomaly alerts.

---

## 🚀 Local Development Setup

### 1. Backend Setup
Since the backend uses `scapy` to capture raw packets, **it must be run with Administrator/Root privileges**.

```bash
# Navigate to the backend directory
cd backend

# Install dependencies
pip install -r requirements.txt

# Run the API server with sudo (Required for live packet sniffing)
sudo python api.py
```
*The backend will run on `http://localhost:8000`.*

### 2. Frontend Setup
```bash
# Navigate to the frontend directory
cd frontend

# Install dependencies
npm install

# Start the Vite development server
npm run dev
```
*The frontend will run on `http://localhost:5173`. It will automatically connect to your local backend.*

---

## ☁️ Production Deployment

Because the backend requires raw socket access (`sudo`), it **cannot** be deployed on serverless platforms (like Vercel, AWS Lambda, or Heroku). It must be hosted on a Virtual Private Server (VPS) such as AWS EC2.

### Backend (AWS EC2)
1. Launch an Ubuntu EC2 instance and open port `8000` in your Security Group.
2. SSH into your EC2 instance and clone the repository.
3. Run the automated setup script to install all OS and Python dependencies:
   ```bash
   chmod +x setup-ec2.sh
   ./setup-ec2.sh
   ```
4. Start the backend server:
   ```bash
   cd backend
   sudo python3 api.py
   ```
   *(We recommend running this in `tmux` or using `sudo nohup` so it stays alive when you close the SSH terminal).*

### Frontend (Vercel)
The frontend is pre-configured for Vercel deployment.
1. Connect this repository to your Vercel account.
2. Ensure Vercel detects the framework as **Vite** and the Root Directory is set to `frontend`.
3. Add an Environment Variable in Vercel:
   - **Name:** `VITE_API_URL`
   - **Value:** `http://<YOUR_EC2_PUBLIC_IP>:8000/api`
4. Deploy!

---

## 📁 Directory Structure

- `/backend` - FastAPI server, Scapy live sniffer, and API routes.
- `/frontend` - React/Vite web application.
- `/Model` - Pickled machine learning models and data scalers.
- `setup-ec2.sh` - Automated shell script for EC2 environment provisioning.
