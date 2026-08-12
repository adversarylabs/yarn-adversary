FROM node:22 AS build
COPY yarn.lock package.json /app/
WORKDIR /app
RUN yarn install --immutable
