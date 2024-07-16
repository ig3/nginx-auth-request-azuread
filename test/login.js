'use strict';

// Test route: GET /login
//
// This route returns the login page, allowing the user to select an
// authentication provider from among those configured.
//

const fs = require('fs');
const path = require('path');
const config = JSON.parse(
  fs.readFileSync(path.join(__dirname, '/data/config1.json'))
);
const t = require('@ig3/test');
const app = require('../app')(config);
const jwt = require('jsonwebtoken');
const http = require('http');
const axios = require('axios');

const server = http.createServer(app);
server.listen(0, '127.0.0.1');
server.on('listening', () => {
  const addr = server.address();
  const address = addr.address;
  const port = addr.port;
  console.log('addr: ', addr);
  console.log('listening on ' + address + ':' + port);
  runTests(port)
  .then(() => {
    console.log('close server');
    server.close();
  })
  .catch(err => {
    console.log('tests failed with: ', err);
  });
});

async function runTests (port) {
  console.log('runTests');
  const request = axios.create({
    baseURL: 'http://localhost:' + port + '/'
  });

  await t.test('verify returns 200', (t) => {
    const token = jwt.sign({}, config.jwtSecret, { expiresIn: config.jwtExpiry });
    return request({
      url: '/verify',
      headers: { Cookie: 'authToken=' + token }
    })
    .then(res => {
      t.equal(res.status, 200, 'Status is 200');
      t.ok(!res.headers['set-cookie'], 'response does not set any cookies');
    })
    .catch(err => {
      console.log('err: ', err);
      t.fail(err);
    })
    .finally(() => {
      t.end();
    });
  });

  await t.test('verify returns new JWT if existing JWT is near expiry', (t) => {
    const token = jwt.sign({
      exp: Math.floor(Date.now() / 1000) + 60 * 9
    }, config.jwtSecret);
    return request({
      url: '/verify',
      headers: {
        Cookie: 'authToken=' + token
      }
    })
    .then(res => {
      t.equal(res.status, 200, 'Status is 200');
      t.ok(res.headers['set-cookie'][0].startsWith('authToken='), 'response includes authToken cookie');
    })
    .catch(err => {
      t.fail(err);
    })
    .finally(() => {
      t.end();
    });
  });

  await t.test('verify returns 401 if no JWT', (t) => {
    return request({
      url: '/verify'
    })
    .then(res => {
      t.fail(res);
    })
    .catch(err => {
      t.ok(!!err.response, 'should get a response');
      t.equal(err.response.status, 401, 'Response status should be 401');
    })
    .finally(() => {
      t.end();
    });
  });

  await t.test('verify returns 401 if invalid authToken', (t) => {
    const origLog = console.log;
    console.log = (...args) => {
      origLog(...args);
    };
    return request({
      url: '/verify',
      headers: {
        Cookie: 'authToken=asdf'
      }
    })
    .then(res => {
      t.fail(res);
    })
    .catch(err => {
      t.ok(!!err.response, 'should get a response');
      t.equal(err.response.status, 401, 'Response status should be 401');
    })
    .finally(() => {
      t.end();
    });
  });
}
