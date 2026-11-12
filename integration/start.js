'use strict';
const { randomBytes } = require('node:crypto');
const os = require('node:os');
process.env.MONGOMS_VERSION = process.env.MONGOMS_VERSION || '7.0.24';
if (process.env.MONGOD_BINARY) process.env.MONGOMS_SYSTEM_BINARY = process.env.MONGOD_BINARY;
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const path = require('node:path');

async function start() {
  process.env.NODE_ENV = 'test'; // Disable outbound SMTP checks and noisy request logs.
  process.env.JWT_SECRET = process.env.JWT_SECRET || randomBytes(32).toString('hex');
  const mongo = await MongoMemoryServer.create({ instance: { launchTimeout: 60000 } });
  process.env.MONGODB_URL = mongo.getUri('gdpr-integration').replace(/\/$/, '');
  const config = require('../src/config/config');
  await mongoose.connect(config.mongoose.url, config.mongoose.options);
  const app = require('../src/app');
  const server = app.listen(Number(process.env.PORT || 3000), '127.0.0.1', () => {
    console.log('Integration backend: http://127.0.0.1:' + server.address().port);
    console.log('MongoDB is temporary; user and consent records disappear when stopped.');
    if (process.send) process.send({ port: server.address().port, mongoUri: config.mongoose.url });
  });
  async function stop() {
    await new Promise(resolve => server.close(resolve));
    await mongoose.disconnect();
    await mongo.stop();
    process.exit(0);
  }
  process.on('message', message => { if (message === 'stop') stop(); });
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
start().catch(error => { console.error(error); process.exit(1); });
