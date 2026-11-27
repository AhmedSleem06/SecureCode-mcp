'use strict';

var Module = require('module');
var pathMod = require('path');
var http = require('http');
var Stream = require('stream');

var _mocks = {};
var _loaded = false;
var _originalLoad = Module._load;
var _callLog = [];
var _callLogCap = 50;
var _harnessUsed = false;
var _engine = 'emulated';
var _unsupported = [];

var _realApp = null;
var _realApps = [];

var _emuApp = null;
var _emuAppStack = [];
var _emuRouteIndex = [];

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

function flattenArgs(args) {
  var out = [];
  for (var i = 0; i < args.length; i++) {
    if (Array.isArray(args[i])) {
      var inner = flattenArgs(args[i]);
      for (var j = 0; j < inner.length; j++) out.push(inner[j]);
    } else {
      out.push(args[i]);
    }
  }
  return out;
}

function recordUnsupported(tag) {
  for (var i = 0; i < _unsupported.length; i++) {
    if (_unsupported[i] === tag) return;
  }
  _unsupported.push(tag);
}

function checkPathSupport(p) {
  if (typeof p !== 'string') {
    if (p instanceof RegExp) { recordUnsupported('regexp path ' + p); return; }
    if (Array.isArray(p)) { recordUnsupported('array path'); return; }
    return;
  }
  if (/[*?+({]/.test(p)) recordUnsupported('wildcard path ' + p);
  if (/:[^/]+[?+*({]/.test(p)) recordUnsupported('optional/modifier param in ' + p);
}

function checkPrefixSupport(prefix) {
  if (typeof prefix !== 'string') return;
  if (/:[^/]/.test(prefix)) recordUnsupported('parameterised use-prefix ' + prefix);
  if (/[*?+({]/.test(prefix)) recordUnsupported('wildcard path ' + prefix);
}

function makeRouter(opts) {
  if (opts && typeof opts === 'object' && Object.keys(opts).length > 0) {
    recordUnsupported('Router options ' + JSON.stringify(opts));
  }
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
      checkPrefixSupport(prefix);
    }
    var flat = flattenArgs(args);
    for (var i = 0; i < flat.length; i++) {
      var fn = flat[i];
      if (typeof fn === 'function') {
        if (fn._scIsRouter && prefix) {
          recordUnsupported('mounted router at ' + prefix);
        }
        stack.push({ type: 'middleware', prefix: prefix, handler: fn, isError: fn.length >= 4 });
      }
    }
    return router;
  };

  router.param = function () {
    recordUnsupported('router.param');
    return router;
  };

  var methods = ['get', 'post', 'put', 'patch', 'delete', 'all', 'options', 'head'];
  methods.forEach(function (method) {
    router[method] = function () {
      var args = Array.prototype.slice.call(arguments);
      var routePath = args.shift();
      checkPathSupport(routePath);
      var flat = flattenArgs(args);
      var handlers = [];
      for (var i = 0; i < flat.length; i++) {
        if (typeof flat[i] === 'function') handlers.push(flat[i]);
      }
      var upperMethod = method === 'all' ? 'ALL' : method.toUpperCase();
      var entry = { type: 'route', method: upperMethod, path: routePath, handlers: handlers };
      stack.push(entry);
      _emuRouteIndex.push(entry);
      return router;
    };
  });

  router.route = function (routePath) {
    checkPathSupport(routePath);
    var chain = {};
    methods.forEach(function (method) {
      chain[method] = function () {
        var args = Array.prototype.slice.call(arguments);
        var flat = flattenArgs(args);
        var handlers = [];
        for (var i = 0; i < flat.length; i++) {
          if (typeof flat[i] === 'function') handlers.push(flat[i]);
        }
        var upperMethod = method === 'all' ? 'ALL' : method.toUpperCase();
        var entry = { type: 'route', method: upperMethod, path: routePath, handlers: handlers };
        stack.push(entry);
        _emuRouteIndex.push(entry);
        return chain;
      };
    });
    return chain;
  };

  return router;
}

function makeApp() {
  var app = makeRouter();
  app._scIsApp = true;

  _emuAppStack = app._scStack;

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

  app.param = function () {
    recordUnsupported('app.param');
    return app;
  };

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
    _emuApp = makeApp();
    return _emuApp;
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
  express.Router = function (opts) {
    return makeRouter(opts);
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

function emuRouteMatches(method, reqPath) {
  var upper = method.toUpperCase();
  for (var i = 0; i < _emuRouteIndex.length; i++) {
    var entry = _emuRouteIndex[i];
    if (entry.method !== 'ALL' && entry.method !== upper) continue;
    if (matchPath(entry.path, reqPath)) return true;
  }
  return false;
}

function makeRealExpressWrapper(realExpress) {
  function wrappedExpress() {
    var app = realExpress();
    var origListen = app.listen;
    app.listen = function () {
      var args = Array.prototype.slice.call(arguments);
      var cb = args[args.length - 1];
      if (typeof cb === 'function') cb();
      return {
        close: function (c) { if (typeof c === 'function') c(); },
        address: function () { return { port: 0 }; },
        on: function () { return this; }
      };
    };
    _realApps.push(app);
    _realApp = app;
    return app;
  }

  wrappedExpress.json = realExpress.json;
  wrappedExpress.urlencoded = realExpress.urlencoded;
  wrappedExpress.static = realExpress.static;
  wrappedExpress.raw = realExpress.raw;
  wrappedExpress.text = realExpress.text;
  wrappedExpress.Router = realExpress.Router;
  wrappedExpress.query = realExpress.query;
  wrappedExpress.request = realExpress.request;
  wrappedExpress.response = realExpress.response;
  wrappedExpress.Route = realExpress.Route;
  wrappedExpress.application = realExpress.application;

  return wrappedExpress;
}

function buildUrlFromPathAndQuery(routePath, query) {
  var url = routePath;
  if (query && typeof query === 'object') {
    var parts = [];
    for (var k in query) {
      if (Object.prototype.hasOwnProperty.call(query, k)) {
        parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(String(query[k])));
      }
    }
    if (parts.length > 0) url += '?' + parts.join('&');
  }
  return url;
}

function realRouteMatches(app, method, reqPath) {
  var router = app._router || app.router;
  if (!router || !router.stack) return false;
  var lower = method.toLowerCase();
  function checkStack(stack, remaining) {
    for (var i = 0; i < stack.length; i++) {
      var layer = stack[i];
      if (layer.route) {
        var methods = layer.route.methods || {};
        if (!methods[lower] && !methods.all && !methods._all) continue;
        if (typeof layer.match === 'function') {
          var m = layer.match(remaining);
          if (m && m !== false) return true;
        }
        var routePath = layer.route.path || layer.rawPath;
        if (routePath === remaining) return true;
        try {
          var info = pathToRegex(routePath);
          if (info.re.exec(remaining)) return true;
        } catch (e) {}
        continue;
      }
      if (layer.handle && layer.handle.stack) {
        if (typeof layer.match === 'function') {
          var lm = layer.match(remaining);
          if (!lm && lm !== true) continue;
          var matchedPrefix = '';
          if (lm && typeof lm === 'object' && typeof lm.path === 'string') {
            matchedPrefix = lm.path;
          } else if (lm === true) {
            if (layer.regexp) {
              var src = layer.regexp.source || '';
              var rm = src.match(/^\^\\\/([^\\/?*+({\[]+)/);
              if (rm) matchedPrefix = '/' + rm[1];
            }
          }
          var sub = matchedPrefix ? remaining.slice(matchedPrefix.length) || '/' : remaining;
          if (checkStack(layer.handle.stack, sub)) return true;
        } else {
          var prefix = '';
          if (typeof layer.rawPath === 'string' && layer.rawPath !== '/') {
            prefix = layer.rawPath;
          } else if (layer.regexp) {
            var src2 = layer.regexp.source || '';
            var rm2 = src2.match(/^\^\\\/([^\\/?*+({\[]+)/);
            if (rm2) prefix = '/' + rm2[1];
          }
          if (prefix) {
            if (remaining !== prefix && !remaining.startsWith(prefix + '/')) continue;
            if (checkStack(layer.handle.stack, remaining.slice(prefix.length) || '/')) return true;
          } else {
            if (checkStack(layer.handle.stack, remaining)) return true;
          }
        }
      }
    }
    return false;
  }
  return checkStack(router.stack, reqPath);
}

function invokeReal(app, method, routePath, reqOverrides) {
  reqOverrides = reqOverrides || {};
  var upperMethod = method.toUpperCase();
  var url = buildUrlFromPathAndQuery(reqOverrides.path || routePath, reqOverrides.query);
  var TIMEOUT_MS = 10000;

  var bodyBuf = null;
  var contentType = null;
  var contentLength = null;

  if (reqOverrides.body !== undefined && reqOverrides.body !== null) {
    var callerCt = reqOverrides.headers && Object.keys(reqOverrides.headers).find(function (k) { return k.toLowerCase() === 'content-type'; });
    if (callerCt) {
      contentType = reqOverrides.headers[callerCt];
    }
    if (typeof reqOverrides.body === 'object' && !Buffer.isBuffer(reqOverrides.body)) {
      bodyBuf = Buffer.from(JSON.stringify(reqOverrides.body), 'utf8');
      if (!contentType) contentType = 'application/json';
    } else if (typeof reqOverrides.body === 'string') {
      bodyBuf = Buffer.from(reqOverrides.body, 'utf8');
    } else if (Buffer.isBuffer(reqOverrides.body)) {
      bodyBuf = reqOverrides.body;
    }
    if (bodyBuf) contentLength = String(bodyBuf.length);
  }

  var socket = new Stream.Duplex({
    read: function () {},
    write: function (chunk, enc, cb) { cb(); }
  });
  socket.remoteAddress = '127.0.0.1';
  socket.remotePort = 0;
  socket.encrypted = false;
  socket.setTimeout = function () { return socket; };
  socket.destroy = function () { return socket; };

  var req = new http.IncomingMessage(socket);
  req.method = upperMethod;
  req.url = url;
  req.headers = {};

  if (reqOverrides.headers) {
    for (var k in reqOverrides.headers) {
      req.headers[k.toLowerCase()] = reqOverrides.headers[k];
    }
  }
  if (contentType && !req.headers['content-type']) req.headers['content-type'] = contentType;
  if (contentLength && !req.headers['content-length']) req.headers['content-length'] = contentLength;
  if (!req.headers['host']) req.headers['host'] = 'localhost';

  if (reqOverrides.user !== undefined) {
    req.user = reqOverrides.user;
  }

  var matched = realRouteMatches(app, upperMethod, reqOverrides.path || routePath);

  return new Promise(function (resolve) {
    var settled = false;

    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      var result = {
        sent: false,
        status: undefined,
        body: undefined,
        headers: {},
        error: 'timeout: handler did not respond within ' + TIMEOUT_MS + 'ms',
        timedOut: true,
        matched: matched
      };
      recordCall({ method: upperMethod, path: reqOverrides.path || routePath, matched: matched, sent: false, status: undefined, timedOut: true });
      resolve(result);
    }, TIMEOUT_MS);

    var res = new http.ServerResponse(req);
    var capturedHeaders = {};
    var capturedBody = [];
    var capturedStatus = undefined;
    var responseSent = false;

    var origWriteHead = res.writeHead;
    res.writeHead = function (statusCode) {
      capturedStatus = statusCode;
      var headers = arguments.length > 2 ? arguments[2] : (typeof arguments[1] === 'object' ? arguments[1] : undefined);
      if (headers) {
        for (var h in headers) capturedHeaders[h.toLowerCase()] = headers[h];
      }
      return origWriteHead.apply(res, arguments);
    };

    var origSetHeader = res.setHeader;
    res.setHeader = function (name, val) {
      capturedHeaders[name.toLowerCase()] = val;
      return origSetHeader.call(res, name, val);
    };

    var origWrite = res.write;
    res.write = function (chunk) {
      if (chunk) capturedBody.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      return origWrite.apply(res, arguments);
    };

    var origEnd = res.end;
    res.end = function (chunk) {
      if (chunk && chunk !== '') capturedBody.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      responseSent = true;
      origEnd.apply(res, arguments);
      finish();
      return res;
    };

    function finish() {
      if (settled) return;
      settled = true;
      clearTimeout(timer);

      var status = capturedStatus || res.statusCode;
      var hdrs = Object.assign({}, capturedHeaders);
      var raw = capturedBody.length > 0 ? Buffer.concat(capturedBody).toString('utf8') : undefined;
      var body = raw;
      if (raw !== undefined) {
        var ct = hdrs['content-type'] || '';
        if (/json/i.test(ct)) {
          try { body = JSON.parse(raw); } catch (e) {}
        } else {
          try { body = JSON.parse(raw); } catch (e) {}
        }
      }

      var result = {
        sent: responseSent,
        status: status,
        body: body,
        headers: hdrs,
        error: null,
        timedOut: false,
        matched: matched
      };
      recordCall({ method: upperMethod, path: reqOverrides.path || routePath, matched: matched, sent: responseSent, status: status, timedOut: false });
      resolve(result);
    }

    if (bodyBuf) {
      req.push(bodyBuf);
    }
    req.push(null);

    var handleFn = typeof app.handle === 'function' ? app.handle.bind(app) : app;

    try {
      handleFn(req, res, function done(err) {
        if (err && !responseSent) {
          var errStatus = (typeof err.status === 'number' && err.status) || (typeof err.statusCode === 'number' && err.statusCode) || 500;
          capturedStatus = errStatus;
          responseSent = true;
          var errMsg = err instanceof Error ? err.message : String(err);
          var result2 = {
            sent: true,
            status: errStatus,
            body: undefined,
            headers: capturedHeaders,
            error: errMsg,
            timedOut: false,
            matched: matched
          };
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            recordCall({ method: upperMethod, path: reqOverrides.path || routePath, matched: matched, sent: true, status: errStatus, timedOut: false });
            resolve(result2);
          }
          return;
        }
        if (!responseSent) {
          var result3 = {
            sent: false,
            status: 404,
            body: undefined,
            headers: capturedHeaders,
            error: null,
            timedOut: false,
            matched: matched
          };
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            recordCall({ method: upperMethod, path: reqOverrides.path || routePath, matched: matched, sent: false, status: 404, timedOut: false });
            resolve(result3);
          }
        }
      });
    } catch (e) {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        responseSent = true;
        var errMsg2 = e instanceof Error ? e.message : String(e);
        recordCall({ method: upperMethod, path: reqOverrides.path || routePath, matched: matched, sent: true, status: 500, timedOut: false });
        resolve({ sent: true, status: 500, body: undefined, headers: {}, error: errMsg2, timedOut: false, matched: matched });
      }
    }
  });
}

function invokeEmulated(method, routePath, reqOverrides) {
  var upperMethod = method.toUpperCase();
  reqOverrides = reqOverrides || {};

  var matched = emuRouteMatches(upperMethod, reqOverrides.path || routePath);

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
    app: _emuApp || {}
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
      var result = {
        sent: false,
        status: res._status,
        body: res._body,
        headers: res._headers,
        error: 'timeout: handler did not respond within ' + TIMEOUT_MS + 'ms',
        timedOut: true,
        matched: matched
      };
      recordCall({ method: upperMethod, path: reqOverrides.path || routePath, matched: matched, sent: false, status: res._status, timedOut: true });
      resolve(result);
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
      var result = {
        sent: res._sent,
        status: res._status,
        body: res._body,
        headers: res._headers,
        error: res._error,
        timedOut: false,
        matched: matched
      };
      recordCall({ method: upperMethod, path: reqOverrides.path || routePath, matched: matched, sent: res._sent, status: res._status, timedOut: false });
      resolve(result);
    }

    res.send = function () { origSend.apply(res, arguments); finish(); return res; };
    res.json = function () { origJson.apply(res, arguments); finish(); return res; };
    res.end = function () { origEnd.apply(res, arguments); finish(); return res; };
    res.sendStatus = function () { origSendStatus.apply(res, arguments); finish(); return res; };
    res.redirect = function () { origRedirect.apply(res, arguments); finish(); return res; };

    try {
      runStack(_emuAppStack, req, res, function (err) {
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

function recordCall(entry) {
  _harnessUsed = true;
  if (_callLog.length < _callLogCap) _callLog.push(entry);
}

function mock(name, fakeModule) {
  if (_loaded) throw new Error('sc.mock() must be called before sc.load()');
  _mocks[name] = fakeModule;
}

function load(targetPath) {
  if (_loaded) throw new Error('sc.load() can only be called once');
  _loaded = true;

  _emuAppStack.length = 0;
  _emuRouteIndex.length = 0;
  _emuApp = null;
  _realApp = null;
  _realApps.length = 0;
  _unsupported.length = 0;

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

  var targetDir = pathMod.dirname(resolved);

  var realExpress = null;
  var expressVersion = null;
  if (!_mocks.hasOwnProperty('express')) {
    try {
      var expressPath = require.resolve('express', { paths: [targetDir] });
      realExpress = require(expressPath);
      try {
        var pkgPath = require.resolve('express/package.json', { paths: [targetDir] });
        expressVersion = require(pkgPath).version;
      } catch (e) {}
    } catch (e) {
      realExpress = null;
    }
  }

  var useReal = realExpress !== null;
  if (useReal) {
    _engine = 'express@' + (expressVersion || 'unknown');
  } else {
    _engine = 'emulated';
  }

  var expressModule = useReal ? makeRealExpressWrapper(realExpress) : makeFakeExpress();

  Module._load = function (request, parent, isMain) {
    if (request === 'express') return expressModule;
    if (_mocks.hasOwnProperty(request)) return _mocks[request];
    return _originalLoad.call(this, request, parent, isMain);
  };

  try {
    if (require.cache[resolved]) {
      delete require.cache[resolved];
    }

    var exported = require(resolved);

    if (useReal && !_realApp) {
      if (exported && typeof exported === 'object') {
        var candidate = exported.app || exported.default || exported;
        if (candidate && typeof candidate.handle === 'function') {
          _realApp = candidate;
          _realApps.push(candidate);
        }
      }
    }

    return exported;
  } finally {
    Module._load = _originalLoad;
  }
}

function invoke(method, routePath, reqOverrides) {
  if (_realApp) {
    return invokeReal(_realApp, method, routePath, reqOverrides);
  }
  return invokeEmulated(method, routePath, reqOverrides);
}

function routes() {
  var router = _realApp && (_realApp._router || _realApp.router);
  if (router && router.stack) {
    var out = [];
    function walk(stack, prefix) {
      for (var i = 0; i < stack.length; i++) {
        var layer = stack[i];
        if (layer.route) {
          var methods = Object.keys(layer.route.methods).filter(function (m) { return layer.route.methods[m]; });
          var routePath = prefix + (layer.route.path || layer.rawPath || '');
          for (var j = 0; j < methods.length; j++) {
            out.push(methods[j].toUpperCase() + ' ' + routePath);
          }
        }
        if (layer.handle && layer.handle.stack) {
          var sub = '';
          if (typeof layer.rawPath === 'string' && layer.rawPath !== '/') {
            sub = layer.rawPath;
          } else if (typeof layer.path === 'string' && layer.path !== '/') {
            sub = layer.path;
          } else if (layer.regexp) {
            var src = layer.regexp.source || '';
            var m = src.match(/^\^\\\/([^\\/?*+({\[]+)/);
            if (m) sub = '/' + m[1];
          }
          walk(layer.handle.stack, prefix + sub);
        }
      }
    }
    walk(router.stack, '');
    return out;
  }
  return _emuRouteIndex.map(function (r) {
    return r.method + ' ' + r.path;
  });
}

function jwtIdentities(map) {
  if (_loaded) throw new Error('sc.jwtIdentities() must be called before sc.load()');
  var identities = {};
  for (var key in map) {
    identities[key] = JSON.parse(JSON.stringify(map[key]));
  }
  var JwtError = function (msg) {
    var e = new Error(msg);
    e.name = 'JsonWebTokenError';
    return e;
  };
  mock('jsonwebtoken', {
    verify: function (token, secretOrKey, optionsOrCb, cb) {
      var callback = typeof optionsOrCb === 'function' ? optionsOrCb : cb;
      var raw = token;
      if (typeof raw === 'string' && raw.startsWith('Bearer ')) raw = raw.slice(7);
      if (identities.hasOwnProperty(raw)) {
        var claims = JSON.parse(JSON.stringify(identities[raw]));
        if (typeof callback === 'function') { callback(null, claims); return; }
        return claims;
      }
      var err = JwtError('invalid token');
      if (typeof callback === 'function') { callback(err); return; }
      throw err;
    },
    decode: function (token) {
      var raw = token;
      if (typeof raw === 'string' && raw.startsWith('Bearer ')) raw = raw.slice(7);
      if (identities.hasOwnProperty(raw)) return JSON.parse(JSON.stringify(identities[raw]));
      return null;
    },
    sign: function (payload) {
      return 'signed-' + (payload && payload.sub ? payload.sub : 'token');
    }
  });
}

process.on('exit', function () {
  if (!_harnessUsed) return;
  try {
    var data = JSON.stringify({ calls: _callLog, engine: _engine, unsupported: _unsupported });
    require('fs').writeSync(1, '\nSECURECODE_HARNESS_LOG:' + data + ':SECURECODE_HARNESS_END\n');
  } catch (e) {}
});

exports.mock = mock;
exports.load = load;
exports.invoke = invoke;
exports.routes = routes;
exports.jwtIdentities = jwtIdentities;
