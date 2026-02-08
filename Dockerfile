# Build stage
FROM node:20-slim AS builder

# Install pnpm
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

WORKDIR /app

# Copy workspace config
COPY pnpm-lock.yaml ./
COPY pnpm-workspace.yaml ./
COPY package.json ./

# Copy packages source
COPY packages ./packages
COPY demo ./demo 
# Copy other necessary files
COPY tsconfig.json ./

# Install dependencies (frozen lockfile for reproducibility)
RUN pnpm install --frozen-lockfile

# Build all packages
RUN pnpm build

# Deploy only the clawguard server to a pruned directory
RUN pnpm --filter @clawguard/core --prod deploy /app/pruned

# Runtime stage
FROM node:20-slim

# Create directory structure and set permissions for node user
RUN mkdir -p /app/.logs && chown -R node:node /app

WORKDIR /app

# Copy the pruned production build from builder (ensure ownership)
COPY --from=builder --chown=node:node /app/pruned .

# Switch to non-root user
USER node

# Environment setup
ENV NODE_ENV=production
ENV PORT=3000

# Metadata
EXPOSE 3000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:3000/v1/status || exit 1

# Start server
# Note: The deploy command copies the package.json which has "main": "./dist/index.js"
CMD ["node", "dist/start.js"]
