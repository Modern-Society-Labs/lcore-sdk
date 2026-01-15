# External Services Setup

L{CORE} requires two external services for production deployment. This guide walks through setting up each one.

---

## EigenCloud (TEE Deployment)

EigenCloud provides Trusted Execution Environment (TEE) infrastructure for running the Attestor and Cartesi Node containers with hardware-backed security guarantees.

### Prerequisites

- EigenCloud account ([sign up](https://eigencloud.io))
- Docker images pushed to a container registry
- Environment variables configured

### Step 1: Create an Account

1. Go to [eigencloud.io](https://eigencloud.io)
2. Sign up for an account
3. Complete email verification
4. Set up billing (if required)

### Step 2: Prepare Docker Images

Before deploying, build and push your images:

```bash
# Build Attestor image
docker build -f attestor.dockerfile -t your-registry/lcore-attestor:eigencloud .

# Build Cartesi Node image
docker build -f cartesi-node.dockerfile -t your-registry/lcore-cartesi-node:eigencloud .

# Push to registry
docker push your-registry/lcore-attestor:eigencloud
docker push your-registry/lcore-cartesi-node:eigencloud
```

### Step 3: Deploy Attestor Container

1. **Navigate** to EigenCloud Dashboard → Deployments
2. **Create New Deployment**
3. **Configure**:
   - **Image**: `your-registry/lcore-attestor:eigencloud`
   - **Port**: `8001`
   - **CPU/Memory**: Recommended 2 vCPU, 4GB RAM

4. **Set Environment Variables**:

| Variable | Description |
|----------|-------------|
| `PRIVATE_KEY` or `MNEMONIC` | Wallet credentials |
| `LCORE_ENABLED` | `1` |
| `LCORE_NODE_URL` | Cartesi Node URL (set after deploying Cartesi) |
| `LCORE_RPC_URL` | Your blockchain RPC endpoint |
| `LCORE_DAPP_ADDRESS` | Deployed Cartesi DApp address |
| `LCORE_INPUTBOX_ADDRESS` | `0x59b22D57D4f067708AB0c00552767405926dc768` |
| `LCORE_ADMIN_PRIVATE_KEY` | NaCl private key (base64) |
| `LOG_LEVEL` | `info` |

5. **Deploy** and note the public IP address

### Step 4: Deploy Cartesi Node Container

1. **Create Another Deployment**
2. **Configure**:
   - **Image**: `your-registry/lcore-cartesi-node:eigencloud`
   - **Port**: `10000`
   - **CPU/Memory**: Recommended 2 vCPU, 4GB RAM

3. **Set Environment Variables**:

| Variable | Description |
|----------|-------------|
| `CARTESI_HTTP_ADDRESS` | `0.0.0.0` (required for external access) |
| `CARTESI_BLOCKCHAIN_ID` | `421614` (Arbitrum Sepolia) |
| `CARTESI_BLOCKCHAIN_HTTP_ENDPOINT` | Your RPC HTTP URL |
| `CARTESI_BLOCKCHAIN_WS_ENDPOINT` | Your RPC WebSocket URL |
| `CARTESI_AUTH_MNEMONIC` | Wallet mnemonic for signing |
| `CARTESI_CONTRACTS_APPLICATION_ADDRESS` | Your DApp address |
| `CARTESI_CONTRACTS_INPUT_BOX_ADDRESS` | `0x59b22D57D4f067708AB0c00552767405926dc768` |
| `PROOF_SIGNING_KEY` | 32-byte hex string |

4. **Deploy** and note the public IP address

### Step 5: Link Containers

Update the Attestor's `LCORE_NODE_URL` environment variable to point to the Cartesi Node:

```
LCORE_NODE_URL=http://CARTESI_NODE_IP:10000
```

Restart the Attestor container for changes to take effect.

### Step 6: Verify Deployment

```bash
# Test Attestor
curl http://ATTESTOR_IP:8001/healthcheck

# Test Cartesi Node
curl http://CARTESI_NODE_IP:10000/inspect/...
```

### TEE Attestation

EigenCloud provides hardware attestation. To get your Docker image hash for TEE verification:

```bash
docker inspect --format='{{.Id}}' your-registry/lcore-attestor:eigencloud | cut -d: -f2 | sed 's/^/0x/'
```

This hash can be used for on-chain verification that your code is running in a genuine TEE.

---

## Cartesi (Rollup Infrastructure)

Cartesi provides the deterministic rollup layer where L{CORE} stores attestations in a verifiable SQLite database.

### Prerequisites

- Node.js 20+
- Docker
- Funded wallet on Arbitrum Sepolia (for contract deployment)

### Step 1: Install Cartesi CLI

```bash
npm install -g @cartesi/cli

# Verify installation
cartesi --version
```

### Step 2: Build the RISC-V Image

The Cartesi application must be compiled for the RISC-V architecture:

```bash
cd cartesi

# Build the Cartesi machine image
cartesi build

# This creates .cartesi/ directory with the machine image
```

**Build output:**
- `.cartesi/image/` - Machine image files
- `.cartesi/image.tar` - Compressed machine image

### Step 3: Deploy Contracts

Deploy the Cartesi application contracts to Arbitrum Sepolia:

```bash
# Set your private key
export CARTESI_PRIVATE_KEY=0x...

# Deploy to Arbitrum Sepolia
cartesi deploy --network arbitrum-sepolia
```

**Deployment output** (save these values):
```
Application deployed!
  Application Address: 0xABC123...  <- LCORE_DAPP_ADDRESS
  Authority Address: 0xDEF456...
  History Address: 0x789GHI...
  InputBox Address: 0x59b22D57D4f067708AB0c00552767405926dc768
```

### Step 4: Configure Environment

Update your `.env` with the deployed addresses:

```env
LCORE_DAPP_ADDRESS=0xABC123...
CARTESI_CONTRACTS_APPLICATION_ADDRESS=0xABC123...
CARTESI_CONTRACTS_AUTHORITY_ADDRESS=0xDEF456...
CARTESI_CONTRACTS_HISTORY_ADDRESS=0x789GHI...
CARTESI_CONTRACTS_INPUT_BOX_ADDRESS=0x59b22D57D4f067708AB0c00552767405926dc768
```

### Step 5: Run Cartesi Node Locally (Development)

For local development, you can run the Cartesi node directly:

```bash
cd cartesi

# Start the node
cartesi run

# Or with custom settings
CARTESI_HTTP_ADDRESS=0.0.0.0 cartesi run
```

The node will be available at `http://localhost:10000`.

### Step 6: Production Deployment

For production, the Cartesi Node runs as a Docker container on EigenCloud (see above).

Build the production image:

```bash
# From repository root
docker build -f cartesi-node.dockerfile -t your-registry/lcore-cartesi-node:eigencloud .
```

### Cartesi CLI Reference

| Command | Description |
|---------|-------------|
| `cartesi build` | Build RISC-V machine image |
| `cartesi deploy` | Deploy contracts to blockchain |
| `cartesi run` | Run node locally |
| `cartesi send` | Send input to running node |
| `cartesi --help` | Show all commands |

### Supported Networks

| Network | Chain ID | InputBox Address |
|---------|----------|------------------|
| Arbitrum Sepolia | 421614 | `0x59b22D57D4f067708AB0c00552767405926dc768` |
| Arbitrum One | 42161 | Check Cartesi docs for mainnet addresses |
| Ethereum Sepolia | 11155111 | Check Cartesi docs |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      EigenCloud TEE                          │
│  ┌─────────────────────┐    ┌─────────────────────────┐     │
│  │   Attestor :8001    │───▶│   Cartesi Node :10000   │     │
│  │   - REST API        │    │   - Rollup Server       │     │
│  │   - Reclaim zkTLS   │    │   - SQLite State        │     │
│  │   - Blockchain TX   │    │   - Inspect Queries     │     │
│  └─────────────────────┘    └─────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                    │                       │
                    ▼                       ▼
          ┌─────────────────┐     ┌─────────────────┐
          │ Blockchain RPC  │     │  InputBox       │
          │ (Your Provider) │     │  Contract       │
          └─────────────────┘     └─────────────────┘
                                          │
                                          ▼
                                  ┌─────────────────┐
                                  │ Arbitrum Sepolia│
                                  │   Settlement    │
                                  └─────────────────┘
```

---

## Troubleshooting

### EigenCloud Issues

**Container won't start:**
- Check environment variables are set correctly
- Verify Docker image is accessible from EigenCloud
- Check container logs in dashboard

**Network connectivity:**
- Ensure ports 8001 and 10000 are exposed
- Verify `CARTESI_HTTP_ADDRESS=0.0.0.0` for external access

### Cartesi Issues

**Build fails:**
- Ensure Docker is running
- Check you have sufficient disk space
- Try `cartesi build --verbose` for detailed output

**Deployment fails:**
- Verify wallet has sufficient funds (ETH for gas)
- Check RPC endpoint is accessible
- Ensure correct network is selected

**Node won't sync:**
- Verify contract addresses are correct
- Check blockchain RPC connectivity
- Review node logs for specific errors

---

## Resources

- [EigenCloud Documentation](https://docs.eigencloud.io)
- [Cartesi Documentation](https://docs.cartesi.io)
- [Arbitrum Sepolia Faucet](https://sepoliafaucet.com)
- [L{CORE} Troubleshooting](./LCORE-TROUBLESHOOTING.md)
