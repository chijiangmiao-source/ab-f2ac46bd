# 离线委托因果复核 —— verify 镜像
# 在镜像内：安装依赖 → 规则测试 → 页面构建 → HTTP 冒烟，一次执行后以退出码结束。
FROM node:20-alpine

WORKDIR /app

# 优先利用缓存安装依赖
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/package.json
COPY packages/web/package.json packages/web/package.json
COPY packages/verify/package.json packages/verify/package.json
RUN npm ci --no-audit --no-fund

COPY . .

# 构建内核与页面，随后执行一次性 verify（测试 + 构建 + HTTP 冒烟）
CMD ["npm", "run", "verify"]
