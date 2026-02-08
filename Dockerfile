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

WORKDIR /app

# Copy the pruned production build from builder
COPY --from=builder /app/pruned .

# Environment setup
ENV NODE_ENV=production
ENV PORT=3000

# Metadata
EXPOSE 3000

# Start server
# Note: The deploy command copies the package.json which has "main": "./dist/index.js"
CMD ["node", "dist/start.js"]
