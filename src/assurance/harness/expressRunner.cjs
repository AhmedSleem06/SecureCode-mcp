'use strict';

var Module = require('module');
var pathMod = require('path');

var _mocks = {};
var _loaded = false;
var _appStack = [];
var _routeIndex = [];
var _originalLoad = Module._load;

function pathToRegex(pattern) {
  var paramNames = [];
  var parts = pattern.split('/');
  var regParts = parts.map(function (part) {
    if (part.startsWith(':')) {
      paramNames.push(part.slice(1));
      return '([^/]+)';
    }
    return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  });
  var re = new RegExp('^' + regParts.join('/') + '$');
  return { re: re, paramNames: paramNames };
}

function matchPath(pattern, actual) {
  var info = pathToRegex(pattern);
  var m = info.re.exec(actual);
  if (!m) return null;
  var params = {};
  for (var i = 0; i < info.paramNames.length; i++) {
    params[info.paramNames[i]] = m[i + 1];
  }
  return params;
}

function prefixMatches(prefix, reqPath) {
  if (!prefix || prefix === '/') return true;
  if (reqPath === prefix) return true;
  if (reqPath.startsWith(prefix + '/')) return true;
  return false;
}

function makeRouter() {
  var stack = [];

  function router(req, res, next) {
    runStack(stack, req, res, next, null);
  }

  router._scIsRouter = true;
  router._scStack = stack;

  router.use = function () {
    var args = Array.prototype.slice.call(arguments);
    var prefix = null;
    if (typeof args[0] === 'string') {
      prefix = args.shift();
    }
    for (var i = 0; i < args.length; i++) {
      var fn = args[i];
      if (typeof fn === 'function') {
        stack.push({ type: 'middleware', prefix: prefix, handler: fn, isError: fn.length >= 4 });
      }
    }
    return router;
  };

  var methods = ['get', 'post', 'put', 'patch', 'delete', 'all', 'options', 'head'];
  methods.forEach(function (method) {
    router[method] = function () {
      var args = Array.prototype.slice.call(arguments);
      var routePath = args.shift();
      var handlers = [];
      for (var i = 0; i < args.length; i++) {
        if (typeof args[i] === 'function') handlers.push(args[i]);
      }
      var upperMethod = method === 'all' ? 'ALL' : method.toUpperCase();
      var entry = { type: 'route', method: upperMethod, path: routePath, handlers: handlers };
      stack.push(entry);
      _routeIndex.push(entry);
      return router;
    };
  });

  router.route = function (routePath) {
    var chain = {};
    methods.forEach(function (method) {
      chain[method] = function () {
        var args = Array.prototype.slice.call(arguments);
        var handlers = [];
        for (var i = 0; i < args.length; i++) {
          if (typeof args[i] === 'function') handlers.push(args[i]);
        }
        var upperMethod = method === 'all' ? 'ALL' : method.toUpperCase();
        var entry = { type: 'route', method: upperMethod, path: routePath, handlers: handlers };
        stack.push(entry);
        _routeIndex.push(entry);
        return chain;
      };
    });
    return chain;
  };

  return router;
}

var _app = null;

function makeApp() {
  var app = makeRouter();
  app._scIsApp = true;

  _appStack = app._scStack;

  app.set = function () { return app; };
  app.enable = function () { return app; };
  app.disable = function () { return app; };
  app.engine = function () { return app; };
  app.listen = function () {
    var cb = arguments[arguments.length - 1];
    if (typeof cb === 'function') cb();
    return { close: function (c) { if (typeof c === 'function') c(); }, address: function () { return { port: 0 }; } };
  };
  app.locals = {};
  app.mountpath = '/';

  var origGet = app.get;
  app.get = function () {
    var args = Array.prototype.slice.call(arguments);
    if (args.length === 1 && typeof args[0] === 'string') {
      return undefined;
    }
    return origGet.apply(app, args);
  };

  return app;
}

function makeFakeExpress() {
  function express() {
    _app = makeApp();
    return _app;
  }

  express.json = function () {
    return function (req, res, next) { next(); };
  };
  express.urlencoded = function () {
    return function (req, res, next) { next(); };
  };
  express.static = function () {
    return function (req, res, next) { next(); };
  };
  express.raw = function () {
    return function (req, res, next) { next(); };
  };
  express.text = function () {
    return function (req, res, next) { next(); };
  };
  express.Router = function () {
    return makeRouter();
  };

  return express;
}

function makeResponse() {
  var res = {
    _status: undefined,
    _body: undefined,
    _headers: {},
    _sent: false,
    _error: null
  };

  Object.defineProperty(res, 'statusCode', {
    get: function () { return res._status; },
    set: function (v) { res._status = v; },
    enumerable: true,
    configurable: true
  });

  res.status = function (code) {
    res._status = code;
    return res;
  };

  res.sendStatus = function (code) {
    res._status = code;
    res._body = String(code);
    res._sent = true;
    return res;
  };

  res.json = function (body) {
    if (!res._status) res._status = 200;
    res._body = body;
    res._headers['content-type'] = 'application/json';
    res._sent = true;
    return res;
  };

  res.send = function (body) {
    if (!res._status) res._status = 200;
    res._body = body;
    res._sent = true;
    return res;
  };

  res.end = function (body) {
    if (!res._status) res._status = 200;
    if (body !== undefined) res._body = body;
    res._sent = true;
    return res;
  };

  res.set = res.header = function (name, val) {
    if (typeof name === 'object') {
      for (var k in name) res._headers[k.toLowerCase()] = name[k];
    } else {
      res._headers[name.toLowerCase()] = val;
    }
    return res;
  };

  res.type = function (t) {
    res._headers['content-type'] = t;
    return res;
  };

  res.redirect = function () {
    var args = Array.prototype.slice.call(arguments);
    var statusCode = 302;
    var url;
    if (args.length === 2) {
      statusCode = args[0];
      url = args[1];
    } else {
      url = args[0];
    }
    res._status = statusCode;
    res._headers['location'] = url;
    res._sent = true;
    return res;
  };

  res.cookie = function () { return res; };
  res.clearCookie = function () { return res; };
  res.append = function (name, val) {
    var existing = res._headers[name.toLowerCase()];
    if (existing) {
      res._headers[name.toLowerCase()] = Array.isArray(existing)
        ? existing.concat(val)
        : [existing, val];
    } else {
      res._headers[name.toLowerCase()] = val;
    }
    return res;
  };
  res.links = function () { return res; };
  res.location = function (url) { res._headers['location'] = url; return res; };
  res.vary = function () { return res; };
  res.format = function () { return res; };
  res.attachment = function () { return res; };
  res.download = function () { return res; };
  res.render = function () { return res; };
  res.locals = {};
  res.headersSent = false;

  return res;
}

function runStack(stack, req, res, done, requestMethod) {
  var method = requestMethod || req.method;
  var idx = 0;

  function next(err) {
    if (res._sent) {
      if (typeof done === 'function') done();
      return;
    }

    while (idx < stack.length) {
      var entry = stack[idx++];

      if (entry.type === 'middleware') {
        if (entry.prefix && !prefixMatches(entry.prefix, req.path || req.url)) continue;

        if (err) {
          if (!entry.isError) continue;
          try {
            var errResult = entry.handler(err, req, res, next);
            if (errResult && typeof errResult.then === 'function') {
              errResult.catch(function (e) { next(e); });
            }
          } catch (e) {
            err = e;
            continue;
          }
          return;
        }

        if (entry.isError) continue;

        if (entry.handler._scIsRouter) {
          try {
            entry.handler(req, res, function (routerErr) {
              if (routerErr) return next(routerErr);
              next();
            });
          } catch (e) {
            err = e;
            continue;
          }
          return;
        }

        try {
          var mwResult = entry.handler(req, res, function nextArg(arg) {
            if (arg === 'route') {
              next();
              return;
            }
            if (arg) {
              next(arg);
            } else {
              next();
            }
          });
          if (mwResult && typeof mwResult.then === 'function') {
            mwResult.catch(function (e) { next(e); });
          }
        } catch (e) {
          err = e;
          continue;
        }
        return;
      }

      if (entry.type === 'route') {
        if (err) continue;
        if (entry.method !== 'ALL' && entry.method !== method) continue;
        var routeParams = matchPath(entry.path, req.path || req.url);
        if (!routeParams) continue;

        Object.assign(req.params, routeParams);
        var handlers = entry.handlers;
        var hi = 0;
        var skipRoute = false;

        function routeNext(routeErr) {
          if (res._sent || skipRoute) return;
          if (routeErr) {
            if (routeErr === 'route') {
              skipRoute = true;
              next();
              return;
            }
            next(routeErr);
            return;
          }
          if (hi >= handlers.length) {
            next();
            return;
          }
          var handler = handlers[hi++];
          try {
            var hResult = handler(req, res, routeNext);
            if (hResult && typeof hResult.then === 'function') {
              hResult.catch(function (e) { routeNext(e); });
            }
          } catch (e) {
            routeNext(e);
          }
        }

        routeNext();
        return;
      }
    }

    if (err && !res._sent) {
      res._status = 500;
      res._error = err instanceof Error ? err.message : String(err);
      res._sent = true;
    }

    if (typeof done === 'function') done(err);
  }

  next();
}

function mock(name, fakeModule) {
  if (_loaded) throw new Error('sc.mock() must be called before sc.load()');
  _mocks[name] = fakeModule;
}

function load(targetPath) {
  if (_loaded) throw new Error('sc.load() can only be called once');
  _loaded = true;

  _appStack.length = 0;
  _routeIndex.length = 0;
  _app = null;

  var fakeExpress = makeFakeExpress();

  Module._load = function (request, parent, isMain) {
    if (request === 'express') return fakeExpress;
    if (_mocks.hasOwnProperty(request)) return _mocks[request];
    return _originalLoad.call(this, request, parent, isMain);
  };

  try {
    var callerDir;
    try {
      var stack = new Error().stack || '';
      var lines = stack.split('\n');
      for (var i = 1; i < lines.length; i++) {
        var match = lines[i].match(/\((.+?):\d+:\d+\)/) || lines[i].match(/at\s+(.+?):\d+:\d+/);
        if (match) {
          var filePath = match[1];
          if (!filePath.includes('expressRunner')) {
            callerDir = pathMod.dirname(filePath);
            break;
          }
        }
      }
    } catch (e) {}

    if (!callerDir) callerDir = process.cwd();

    var resolved;
    if (targetPath.startsWith('.') || targetPath.startsWith('/') || /^[A-Z]:\\/.test(targetPath)) {
      resolved = require.resolve(pathMod.resolve(callerDir, targetPath));
    } else {
      resolved = require.resolve(targetPath);
    }

    if (require.cache[resolved]) {
      delete require.cache[resolved];
    }

    return require(resolved);
  } finally {
    Module._load = _originalLoad;
  }
}

function invoke(method, routePath, reqOverrides) {
  var upperMethod = method.toUpperCase();
  reqOverrides = reqOverrides || {};

  var req = {
    method: upperMethod,
    url: reqOverrides.url || routePath,
    path: reqOverrides.path || routePath,
    params: reqOverrides.params || {},
    query: reqOverrides.query || {},
    body: reqOverrides.body || {},
    headers: {},
    get: function (name) { return this.headers[name.toLowerCase()]; },
    header: function (name) { return this.headers[name.toLowerCase()]; },
    is: function () { return null; },
    cookies: reqOverrides.cookies || {},
    session: reqOverrides.session || {},
    ip: reqOverrides.ip || '127.0.0.1',
    ips: [],
    hostname: reqOverrides.hostname || 'localhost',
    protocol: 'http',
    secure: false,
    xhr: false,
    app: _app || {}
  };

  if (reqOverrides.headers) {
    for (var k in reqOverrides.headers) {
      req.headers[k.toLowerCase()] = reqOverrides.headers[k];
    }
  }
  if (reqOverrides.user !== undefined) {
    req.user = reqOverrides.user;
  }

  var res = makeResponse();
  var TIMEOUT_MS = 10000;

  return new Promise(function (resolve) {
    var settled = false;
    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      resolve({
        sent: false,
        status: res._status,
        body: res._body,
        headers: res._headers,
        error: 'timeout: handler did not respond within ' + TIMEOUT_MS + 'ms',
        timedOut: true
      });
    }, TIMEOUT_MS);

    var origSend = res.send;
    var origJson = res.json;
    var origEnd = res.end;
    var origSendStatus = res.sendStatus;
    var origRedirect = res.redirect;

    function finish() {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        sent: res._sent,
        status: res._status,
        body: res._body,
        headers: res._headers,
        error: res._error,
        timedOut: false
      });
    }

    res.send = function () { origSend.apply(res, arguments); finish(); return res; };
    res.json = function () { origJson.apply(res, arguments); finish(); return res; };
    res.end = function () { origEnd.apply(res, arguments); finish(); return res; };
    res.sendStatus = function () { origSendStatus.apply(res, arguments); finish(); return res; };
    res.redirect = function () { origRedirect.apply(res, arguments); finish(); return res; };

    try {
      runStack(_appStack, req, res, function (err) {
        if (err && !res._sent) {
          res._status = 500;
          res._error = err instanceof Error ? err.message : String(err);
          res._sent = true;
        }
        finish();
      }, upperMethod);
    } catch (e) {
      if (!res._sent) {
        res._status = 500;
        res._error = e instanceof Error ? e.message : String(e);
        res._sent = true;
      }
      finish();
    }
  });
}

function routes() {
  return _routeIndex.map(function (r) {
    return r.method + ' ' + r.path;
  });
}

exports.mock = mock;
exports.load = load;
exports.invoke = invoke;
exports.routes = routes;
