# Deployment Guide

## 1. Prerequisites
- **Sui CLI**: Install Sui CLI (v1.65.0+).
- **Docker**: Install Docker Engine.
- **Sui Wallet**: Ensure you have a funded wallet on Testnet/Mainnet.

## 2. Deploy Move Contract (Sui Seal Policy)

Deploy the `seal_policy` package to the Sui network. This controls access to encrypted logs.

1.  **Navigate to package directory**:
    ```bash
    cd move/seal_policy
    ```

2.  **Publish Package**:
    ```bash
    sui client publish --gas-budget 100000000 --skip-dependency-verification
    ```

3.  **Save Output**:
    -   Note the **Package ID** (e.g., `0x...`).
    -   Note the **UpgradeCap ID**.
    -   Note the **AccessCap ID**.

4.  **Update Config**:
    -   Set `SEAL_PACKAGE_ID` environment variable to the deployed Package ID.

## 3. Deploy ClawGuard Server (Docker)

Run the server as a containerized service.

1.  **Build Image**:
    ```bash
    # From project root
    docker build -t clawguard/server:latest .
    ```

2.  **Authenticate & Push**:
    ```bash
    # Login to Docker Hub (or your registry)
    docker login

    # Tag and Push
    docker tag clawguard/server:latest <your-registry>/clawguard-server:latest
    docker push <your-registry>/clawguard-server:latest
    ```

3.  **Prepare Run Environment**:
    -   Create a `.env` file or set variables in your deployment platform (e.g., Kubernetes, Fly.io).

    ```env
    PORT=3000
    CLAWGUARDTOKEN=your-secret-token
    # Seal Package ID (Deployed on Testnet)
    SEAL_PACKAGE_ID=0x5379bf93b2b4733478e126f377d43b4cdc69ef6de7d7d163412fd3a0007c3fb2
    # Optional: Log directory (will be inside container)
    LOGDIR=.logs
    # Optional: Policy path (mount this volume)
    POLICY_PATH=/app/policy.yaml
    ```

3.  **Run Container**:
    ```bash
    # Prepare logs directory with correct permissions (UID 1000 is 'node' user)
    mkdir logs
    sudo chown -R 1000:1000 logs

    docker run -d \
      -p 3000:3000 \
      --env-file .env \
      -v $(pwd)/.logs:/app/.logs \
      -v $(pwd)/packages/clawguard/policy.yaml:/app/policy.yaml:ro \
      --name clawguard-server \
      --health-cmd="curl -f http://localhost:3000/v1/status || exit 1" \
      jayjoshix/clawguard-server:latest
    ```

4.  **Verify**:
    ```bash
    curl http://localhost:3000/v1/status
    ```

## 4. Production Considerations

-   **Persistence**: Mount the `.logs` directory to a persistent volume (PVC, EBS, etc.) to ensure the hash chain survives restarts.
-   **Security**: Rotate `CLAWGUARDTOKEN` and ensure `server-key.json` (inside `.logs`) is backed up if identity persistence is critical.
-   **SSL/TLS**: Terminate SSL at a load balancer or reverse proxy (Nginx) in front of the container.
