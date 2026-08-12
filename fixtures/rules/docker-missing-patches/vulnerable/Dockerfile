FROM node:22 AS build
RUN mkdir -p /base/yarn-ui
COPY ui/yarn.lock ui/package.json /base/yarn-ui/
WORKDIR /base/yarn-ui
RUN yarn install --immutable
