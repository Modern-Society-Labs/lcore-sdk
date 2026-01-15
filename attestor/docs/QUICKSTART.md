# L{CORE} Quick Start Guide

Get L{CORE} running in production in under 15 minutes.

## Prerequisites

Before starting, ensure you have:

- **Node.js 20+** and npm
- **Docker** installed and running
- **Funded wallet** on Arbitrum Sepolia (for contract deployment)
- **EigenCloud account** (sign up at [eigencloud.io](https://eigencloud.io))
- **Blockchain RPC endpoint** (any provider: Alchemy, Infura, QuickNode, etc.)

---

## Step 1: Clone & Install

```bash
# Clone the repository (or use GitHub's "Use this template" button)
git clone https://github.com/Modern-Society-Labs/lcore-sdk.git my-lcore-app
cd my-lcore-app

# Install Attestor dependencies
npm install

# Install Cartesi dependencies
cd cartesi && npm install && cd ..
```

---

## Step 2: Generate Keys

Generate the required cryptographic keys:

```bash
# Generate NaCl keypair for L{CORE} encryption
node -e "
const nacl = require('tweetnacl');
const kp = nacl.box.keyPair();
console.log('LCORE_ADMIN_PUBLIC_KEY=' + Buffer.from(kp.publicKey).toString('base64'));
console.log('LCORE_ADMIN_PRIVATE_KEY=' + Buffer.from(kp.secretKey).toString('base64'));
"

# Generate proof signing key for Cartesi
node -e "console.log('PROOF_SIGNING_KEY=' + require('crypto').randomBytes(32).toString('hex'))"
```

Save these values - you'll need them in the next step.

---

## Step 3: Configure Environment

```bash
# Copy the example environment file
cp .env.example .env
```

Edit `.env` with your values:

```env
# === REQUIRED ===

# Your wallet private key (for blockchain transactions)
PRIVATE_KEY=0x...

# Your blockchain RPC endpoint
LCORE_RPC_URL=https://your-rpc-provider.com/v2/YOUR_KEY

# L{CORE} encryption keys (from Step 2)
LCORE_ADMIN_PUBLIC_KEY=your-base64-public-key
LCORE_ADMIN_PRIVATE_KEY=your-base64-private-key

# Proof signing key (from Step 2)
PROOF_SIGNING_KEY=your-64-char-hex-string

# === AFTER CARTESI DEPLOYMENT (Step 4) ===
LCORE_DAPP_ADDRESS=0x...  # Will get this after deployment
LCORE_NODE_URL=http://localhost:10000  # Update to production URL after EigenCloud deploy

# InputBox is standard across Arbitrum Sepolia
LCORE_INPUTBOX_ADDRESS=0x59b22D57D4f067708AB0c00552767405926dc768
```

---

## Step 4: Deploy Cartesi Application

### Install Cartesi CLI

```bash
npm install -g @cartesi/cli
```

### Build the RISC-V Image

```bash
cd cartesi

# Build for RISC-V architecture
cartesi build

# This creates the Cartesi machine image
```

### Deploy to Arbitrum Sepolia

```bash
# Deploy contracts (requires funded wallet)
cartesi deploy --network arbitrum-sepolia

# Save the output - you'll need:
# - Application Address (LCORE_DAPP_ADDRESS)
# - Authority Address
# - History Address
```

Update your `.env` with the deployed `LCORE_DAPP_ADDRESS`.

---

## Step 5: Build Docker Images

```bash
# Back to root directory
cd ..

# Build Attestor image for EigenCloud
docker build -f attestor.dockerfile -t your-registry/lcore-attestor:latest .

# Build Cartesi Node wrapper for EigenCloud
docker build -f cartesi-node.dockerfile -t your-registry/lcore-cartesi-node:latest .

# Push to your container registry
docker push your-registry/lcore-attestor:latest
docker push your-registry/lcore-cartesi-node:latest
```

---

## Step 6: Deploy to EigenCloud

1. **Log in** to [EigenCloud Dashboard](https://eigencloud.io)

2. **Create Attestor Container**:
   - Image: `your-registry/lcore-attestor:latest`
   - Port: `8001`
   - Environment variables from your `.env`

3. **Create Cartesi Node Container**:
   - Image: `your-registry/lcore-cartesi-node:latest`
   - Port: `10000`
   - Set `CARTESI_HTTP_ADDRESS=0.0.0.0` for external access
   - Add your Cartesi contract addresses

4. **Note the public IPs** assigned to each container

5. **Update** your Attestor's `LCORE_NODE_URL` to point to the Cartesi Node's public URL

See [EXTERNAL_SERVICES.md](./EXTERNAL_SERVICES.md) for detailed EigenCloud setup instructions.

---

## Step 7: Verify Deployment

### Test Attestor Health

```bash
curl http://YOUR_ATTESTOR_IP:8001/healthcheck
```

Expected response:
```json
{
  "status": "ok",
  "version": "5.0.0",
  "lcore_enabled": true
}
```

### Test Cartesi Node

```bash
# Query all provider schemas
curl "http://YOUR_CARTESI_IP:10000/inspect/$(python3 -c "import urllib.parse; print(urllib.parse.quote('{\"type\":\"all_provider_schemas\",\"params\":{}}'))")"
```

### Register Encryption Key

Register your public key with the Cartesi rollup:

```bash
curl -X POST http://YOUR_ATTESTOR_IP:8001/api/lcore/set-encryption-key \
  -H "Content-Type: application/json" \
  -d '{"publicKey": "your-base64-public-key"}'
```

---

## Next Steps

Your L{CORE} deployment is now live! Here's what to do next:

1. **Create Provider Schemas** - Define what data you want to attest
   - See [provider.md](./provider.md) for schema format

2. **Integrate with Your dApp** - Use the L{CORE} client
   - See [claim-creation.md](./claim-creation.md) for examples

3. **Set Up Access Control** - Configure who can access attested data
   - See [LCORE-ARCHITECTURE.md](./LCORE-ARCHITECTURE.md) for access model

4. **Monitor & Debug** - Check logs and troubleshoot
   - See [LCORE-TROUBLESHOOTING.md](./LCORE-TROUBLESHOOTING.md)

---

## Production Checklist

Before going live:

- [ ] All environment variables set correctly
- [ ] `PROOF_SIGNING_KEY` is unique and secret
- [ ] `LCORE_ADMIN_PRIVATE_KEY` only accessible to TEE
- [ ] Encryption public key registered in Cartesi
- [ ] Health checks passing on both containers
- [ ] Blockchain wallet has sufficient funds for gas

---

## Quick Reference

| Resource | URL |
|----------|-----|
| Attestor API | `http://YOUR_IP:8001` |
| Cartesi Node | `http://YOUR_IP:10000` |
| Health Check | `GET /healthcheck` |
| Inspect Query | `GET /inspect/{encoded_query}` |

| Contract | Address (Arbitrum Sepolia) |
|----------|----------------------------|
| InputBox | `0x59b22D57D4f067708AB0c00552767405926dc768` |
| Your DApp | From `cartesi deploy` output |
