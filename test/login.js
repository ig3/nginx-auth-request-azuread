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
const t = require('tape');
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
    server.close();
  })
  .catch(err => {
    console.log('tests failed with: ', err);
  });
});

function runTests (port) {
  return new Promise((resolve, reject) => {
    const request = axios.create({
      baseURL: 'http://localhost:' + port + '/'
    });

    t.test('verify returns 200', (t) => {
      const token = jwt.sign({}, config.jwtSecret, { expiresIn: config.jwtExpiry });
      request({
        url: '/verify',
        headers: { Cookie: 'authToken=' + token }
      })
      .then(res => {
        t.equal(res.status, 200, 'Status is 200');
        t.ok(!res.headers['set-cookie'], 'response does not set any cookies');
      })
      .catch(err => {
        t.fail(err);
      })
      .finally(() => {
        t.end();
      });
    });

    t.test('verify returns new JWT if existing JWT is near expiry', (t) => {
      const token = jwt.sign({
        exp: Math.floor(Date.now() / 1000) + 60 * 9
      }, config.jwtSecret);
      request({
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

    t.test('verify returns 401 if no JWT', (t) => {
      request({
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

    t.test('verify returns 401 if invalid authToken', (t) => {
      const origLog = console.log;
      console.log = (...args) => {
        origLog(...args);
      };
      request({
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

    t.onFinish(() => {
      resolve();
    });

    t.onFailure(() => {
      reject(new Error('something went wrong'));
    });
  });
}
