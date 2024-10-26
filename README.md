# Secure Restful APIs Communication

This repository contains an example to showcase showcase a secure message exchange between Restful APIs through encryption and signature.

## Prerequisites

- [NodeJS](https://nodejs.org/)
- [Docker](https://www.docker.com/)

## Getting started

### With NodeJS

To start the example APIs with NodeJS, you should install dependencies with `npm start`, and then start the [ExpressJS](https://expressjs.com/) APIs with `npm run start:all`

API 1 will be listening on `http//localhost:3000`.

API 2 will be listening on `http//localhost:4000`.

### With Docker

To start the example APIs with Docker, just execute the command `docker:start-all`.This will build Docker images for both APIs and run them in two containers.

API 1 will be listening on `http//localhost:3000`.

API 2 will be listening on `http//localhost:4000`.

## Sending and receiving messages

Both APIs expose two endpoints, one for sending a message to the other API, and one to receive a message.

- `/send-message` - Sends an encrypted and signed message to another API.
- `receive-message` - Receive, validata and decrypt the received message.

You can use the exported Postman [collection](./Secure_Restful_APIs_Communication.postman_collection.json) and [environment](./Secure_Restful_APIs_Communication.postman_environment.json) to send messages to any of both APIs, and to exchange messages between them.

## Creating certificates

This module is provided with example RSA 2048 certificates for both API 1 and API 2, but you may want to generate your own certificates.

To generate RSA 2048 certificates follow this steps:

`cd certs`

### API 1

`openssl genrsa -out api_1_private_key.pem 2048`

`openssl rsa -in api_1_private_key.pem -pubout -out api_1_public_key.pem`

### API 2

`openssl genrsa -out api_2_private_key.pem 2048`

`openssl rsa -in api_2_private_key.pem -pubout -out api_2_public_key.pem`
