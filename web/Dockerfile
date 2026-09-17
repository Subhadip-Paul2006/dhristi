FROM node:22-slim

WORKDIR /srv
# M10b: use `npm ci` for reproducible installs from the committed package-lock.json.
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# M10a: drop root for the runtime process. The node image ships an unprivileged
# `node` user; hand it ownership of the built app so it can serve the files.
RUN chown -R node:node /srv
USER node

EXPOSE 5173

# M10c: report unhealthy if the preview server stops responding.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD node -e "require('http').get('http://127.0.0.1:5173/',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))"

CMD ["npm", "run", "preview"]
