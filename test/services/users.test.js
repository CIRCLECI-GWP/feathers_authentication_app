const axios = require('axios');
const url = require('url');
const app = require('../../src/app');
const port = app.get('port') || 8998;
const getUrl = (pathname) =>
  url.format({
    hostname: app.get('host') || 'localhost',
    protocol: 'http',
    port,
    pathname,
  });
describe('\'users\' service', () => {
  it('registered the service', () => {
    const service = app.service('users');
    expect(service).toBeTruthy();
  });
});
describe('Additional security checks on user endpoints', () => {
  let alice = {
    email: 'alice@feathersjs.com',
    password: 'supersecret12',
  };
  let bob = {
    email: 'bob@feathersjs.com',
    password: 'supersecret1',
  };
  const getTokenForUser = async (user) => {
    const { accessToken } = await app.service('authentication').create({
      strategy: 'local',
      ...user,
    });
    return accessToken;
  };
  const setupUser = async (user) => {
    const { _id } = await app.service('users').create(user);
    user._id = _id;
    user.accessToken = await getTokenForUser(user);
  };
  let server;
  beforeAll(async (done) => {
    await setupUser(alice);
    await setupUser(bob);
    server = app.listen(port);
    server.once('listening', () => done());
  });
  afterAll(async (done) => {
    server.close(done);
  });
  it('should return 403 when user tries to delete another user', async () => {
    expect.assertions(2);
    const { accessToken } = alice;
    const { _id: targetId } = bob;
    const config = { headers: { Authorization: `Bearer ${accessToken}` } };
    try {
      await axios.delete(getUrl(`/users/${targetId}`), config);
    } catch (error) {
      const { response } = error;
      expect(response.status).toBe(403);
      expect(response.data.message).toBe(
        'You are not authorized to perform this operation on another user'
      );
    }
  });
  it('should return 403 when user tries to put another user', async () => {
    expect.assertions(2);
    try {
      const { accessToken } = bob;
      const { _id: targetId } = alice;
      const config = { headers: { Authorization: `Bearer ${accessToken}` } };
      const testData = { password: bob.password };
      await axios.put(getUrl(`/users/${targetId}`), testData, config);
    } catch (error) {
      const { response } = error;
      expect(response.status).toBe(403);
      expect(response.data.message).toBe(
        'You are not authorized to perform this operation on another user'
      );
    }
  });
  it('should return 403 when user tries to patch another user', async () => {
    expect.assertions(2);
    try {
      const { accessToken } = alice;
      const { _id: targetId } = bob;
      const config = { headers: { Authorization: `Bearer ${accessToken}` } };
      const testData = { password: alice.password };
      await axios.patch(getUrl(`/users/${targetId}`), testData, config);
    } catch (error) {
      console.log(error);
      const { response } = error;
      expect(response.status).toBe(403);
      expect(response.data.message).toBe(
        'You are not authorized to perform this operation on another user'
      );
    }
  });
});
