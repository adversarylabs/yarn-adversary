FROM node:22 AS build
COPY ui/yarn.lock ui/package.json /base/yarn-ui/
COPY ui/.yarn/patches /base/yarn-ui/.yarn/patches/
WORKDIR /base/yarn-ui
RUN yarn install --immutable
