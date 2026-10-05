FROM node:20-alpine

WORKDIR /app

# Install dependencies (devDependencies are needed for esbuild + jsdom).
COPY package.json package-lock.json ./
RUN npm ci

# Copy sources.
COPY core ./core
COPY web ./web
COPY tests ./tests
COPY tools ./tools
COPY verify ./verify

# The one-shot verification job: rule tests, page build, then HTTP smoke.
# It runs exactly once and the container exits with its result code.
CMD ["node", "verify/verify.mjs"]
