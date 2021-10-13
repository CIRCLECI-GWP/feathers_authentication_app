const { authenticate } = require('@feathersjs/authentication').hooks;

const { Forbidden } = require('@feathersjs/errors');

const {
  hashPassword, protect
} = require('@feathersjs/authentication-local').hooks;

const verifyCanPerformOperation = async context => {
  const {_id: authenticatedUserId} = context.params.user;
  const {id: targetUserId} = context;
  if (authenticatedUserId !== targetUserId) {
    throw new Forbidden('You are not authorized to perform this operation on another user');
  }
};

module.exports = {
  before: {
    all: [],
    find: [authenticate('jwt')],
    get: [authenticate('jwt')],
    create: [hashPassword('password')],
    update: [hashPassword('password'), authenticate('jwt'), verifyCanPerformOperation],
    patch: [hashPassword('password'), authenticate('jwt'), verifyCanPerformOperation],
    remove: [authenticate('jwt'), verifyCanPerformOperation]
  },

  after: {
    all: [
      // Make sure the password field is never sent to the client
      // Always must be the last hook
      protect('password')
    ],
    find: [],
    get: [],
    create: [],
    update: [],
    patch: [],
    remove: []
  },

  error: {
    all: [],
    find: [],
    get: [],
    create: [],
    update: [],
    patch: [],
    remove: []
  }
};
