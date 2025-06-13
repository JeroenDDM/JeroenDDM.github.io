(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
  typeof define === 'function' && define.amd ? define(factory) :
  (global = global || self, (global.purecloud = global.purecloud || {}, global.purecloud.apps = global.purecloud.apps || {}, global.purecloud.apps.ClientApp = factory()));
}(this, (function () { 'use strict';

  /*
  * purecloud-client-app-sdk
  * @copyright Copyright (C) 2024 Genesys Telecommunications Laboratories, Inc.}
  * @license MIT
  *
  * This software comprises other FOSS software.
  * Attribution and license information can be found at https://github.com/MyPureCloud/client-app-sdk/blob/master/README.md
  */

  function _classCallCheck(instance, Constructor) {
    if (!(instance instanceof Constructor)) {
      throw new TypeError("Cannot call a class as a function");
    }
  }

  var classCallCheck = _classCallCheck;

  function _defineProperties(target, props) {
    for (var i = 0; i < props.length; i++) {
      var descriptor = props[i];
      descriptor.enumerable = descriptor.enumerable || false;
      descriptor.configurable = true;
      if ("value" in descriptor) descriptor.writable = true;
      Object.defineProperty(target, descriptor.key, descriptor);
    }
  }

  function _createClass(Constructor, protoProps, staticProps) {
    if (protoProps) _defineProperties(Constructor.prototype, protoProps);
    if (staticProps) _defineProperties(Constructor, staticProps);
    return Constructor;
  }

  var createClass = _createClass;

  function _defineProperty(obj, key, value) {
    if (key in obj) {
      Object.defineProperty(obj, key, {
        value: value,
        enumerable: true,
        configurable: true,
        writable: true
      });
    } else {
      obj[key] = value;
    }

    return obj;
  }

  var defineProperty = _defineProperty;

  var commonjsGlobal = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

  function unwrapExports (x) {
  	return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, 'default') ? x['default'] : x;
  }

  function createCommonjsModule(fn, basedir, module) {
  	return module = {
  	  path: basedir,
  	  exports: {},
  	  require: function (path, base) {
        return commonjsRequire(path, (base === undefined || base === null) ? module.path : base);
      }
  	}, fn(module, module.exports), module.exports;
  }

  function commonjsRequire () {
  	throw new Error('Dynamic requires are not currently supported by @rollup/plugin-commonjs');
  }

  var strictUriEncode = str => encodeURIComponent(str).replace(/[!'()*]/g, x => `%${x.charCodeAt(0).toString(16).toUpperCase()}`);

  var token = '%[a-f0-9]{2}';
  var singleMatcher = new RegExp('(' + token + ')|([^%]+?)', 'gi');
  var multiMatcher = new RegExp('(' + token + ')+', 'gi');

  function decodeComponents(components, split) {
  	try {
  		// Try to decode the entire string first
  		return [decodeURIComponent(components.join(''))];
  	} catch (err) {
  		// Do nothing
  	}

  	if (components.length === 1) {
  		return components;
  	}

  	split = split || 1;

  	// Split the array in 2 parts
  	var left = components.slice(0, split);
  	var right = components.slice(split);

  	return Array.prototype.concat.call([], decodeComponents(left), decodeComponents(right));
  }

  function decode(input) {
  	try {
  		return decodeURIComponent(input);
  	} catch (err) {
  		var tokens = input.match(singleMatcher) || [];

  		for (var i = 1; i < tokens.length; i++) {
  			input = decodeComponents(tokens, i).join('');

  			tokens = input.match(singleMatcher) || [];
  		}

  		return input;
  	}
  }

  function customDecodeURIComponent(input) {
  	// Keep track of all the replacements and prefill the map with the `BOM`
  	var replaceMap = {
  		'%FE%FF': '\uFFFD\uFFFD',
  		'%FF%FE': '\uFFFD\uFFFD'
  	};

  	var match = multiMatcher.exec(input);
  	while (match) {
  		try {
  			// Decode as big chunks as possible
  			replaceMap[match[0]] = decodeURIComponent(match[0]);
  		} catch (err) {
  			var result = decode(match[0]);

  			if (result !== match[0]) {
  				replaceMap[match[0]] = result;
  			}
  		}

  		match = multiMatcher.exec(input);
  	}

  	// Add `%C2` at the end of the map to make sure it does not replace the combinator before everything else
  	replaceMap['%C2'] = '\uFFFD';

  	var entries = Object.keys(replaceMap);

  	for (var i = 0; i < entries.length; i++) {
  		// Replace all decoded components
  		var key = entries[i];
  		input = input.replace(new RegExp(key, 'g'), replaceMap[key]);
  	}

  	return input;
  }

  var decodeUriComponent = function (encodedURI) {
  	if (typeof encodedURI !== 'string') {
  		throw new TypeError('Expected `encodedURI` to be of type `string`, got `' + typeof encodedURI + '`');
  	}

  	try {
  		encodedURI = encodedURI.replace(/\+/g, ' ');

  		// Try the built in decoder first
  		return decodeURIComponent(encodedURI);
  	} catch (err) {
  		// Fallback to a more advanced decoder
  		return customDecodeURIComponent(encodedURI);
  	}
  };

  var splitOnFirst = (string, separator) => {
  	if (!(typeof string === 'string' && typeof separator === 'string')) {
  		throw new TypeError('Expected the arguments to be of type `string`');
  	}

  	if (separator === '') {
  		return [string];
  	}

  	const separatorIndex = string.indexOf(separator);

  	if (separatorIndex === -1) {
  		return [string];
  	}

  	return [
  		string.slice(0, separatorIndex),
  		string.slice(separatorIndex + separator.length)
  	];
  };

  var filterObj = function (obj, predicate) {
  	var ret = {};
  	var keys = Object.keys(obj);
  	var isArr = Array.isArray(predicate);

  	for (var i = 0; i < keys.length; i++) {
  		var key = keys[i];
  		var val = obj[key];

  		if (isArr ? predicate.indexOf(key) !== -1 : predicate(key, val, obj)) {
  			ret[key] = val;
  		}
  	}

  	return ret;
  };

  var queryString = createCommonjsModule(function (module, exports) {





  const isNullOrUndefined = value => value === null || value === undefined;

  const encodeFragmentIdentifier = Symbol('encodeFragmentIdentifier');

  function encoderForArrayFormat(options) {
  	switch (options.arrayFormat) {
  		case 'index':
  			return key => (result, value) => {
  				const index = result.length;

  				if (
  					value === undefined ||
  					(options.skipNull && value === null) ||
  					(options.skipEmptyString && value === '')
  				) {
  					return result;
  				}

  				if (value === null) {
  					return [...result, [encode(key, options), '[', index, ']'].join('')];
  				}

  				return [
  					...result,
  					[encode(key, options), '[', encode(index, options), ']=', encode(value, options)].join('')
  				];
  			};

  		case 'bracket':
  			return key => (result, value) => {
  				if (
  					value === undefined ||
  					(options.skipNull && value === null) ||
  					(options.skipEmptyString && value === '')
  				) {
  					return result;
  				}

  				if (value === null) {
  					return [...result, [encode(key, options), '[]'].join('')];
  				}

  				return [...result, [encode(key, options), '[]=', encode(value, options)].join('')];
  			};

  		case 'colon-list-separator':
  			return key => (result, value) => {
  				if (
  					value === undefined ||
  					(options.skipNull && value === null) ||
  					(options.skipEmptyString && value === '')
  				) {
  					return result;
  				}

  				if (value === null) {
  					return [...result, [encode(key, options), ':list='].join('')];
  				}

  				return [...result, [encode(key, options), ':list=', encode(value, options)].join('')];
  			};

  		case 'comma':
  		case 'separator':
  		case 'bracket-separator': {
  			const keyValueSep = options.arrayFormat === 'bracket-separator' ?
  				'[]=' :
  				'=';

  			return key => (result, value) => {
  				if (
  					value === undefined ||
  					(options.skipNull && value === null) ||
  					(options.skipEmptyString && value === '')
  				) {
  					return result;
  				}

  				// Translate null to an empty string so that it doesn't serialize as 'null'
  				value = value === null ? '' : value;

  				if (result.length === 0) {
  					return [[encode(key, options), keyValueSep, encode(value, options)].join('')];
  				}

  				return [[result, encode(value, options)].join(options.arrayFormatSeparator)];
  			};
  		}

  		default:
  			return key => (result, value) => {
  				if (
  					value === undefined ||
  					(options.skipNull && value === null) ||
  					(options.skipEmptyString && value === '')
  				) {
  					return result;
  				}

  				if (value === null) {
  					return [...result, encode(key, options)];
  				}

  				return [...result, [encode(key, options), '=', encode(value, options)].join('')];
  			};
  	}
  }

  function parserForArrayFormat(options) {
  	let result;

  	switch (options.arrayFormat) {
  		case 'index':
  			return (key, value, accumulator) => {
  				result = /\[(\d*)\]$/.exec(key);

  				key = key.replace(/\[\d*\]$/, '');

  				if (!result) {
  					accumulator[key] = value;
  					return;
  				}

  				if (accumulator[key] === undefined) {
  					accumulator[key] = {};
  				}

  				accumulator[key][result[1]] = value;
  			};

  		case 'bracket':
  			return (key, value, accumulator) => {
  				result = /(\[\])$/.exec(key);
  				key = key.replace(/\[\]$/, '');

  				if (!result) {
  					accumulator[key] = value;
  					return;
  				}

  				if (accumulator[key] === undefined) {
  					accumulator[key] = [value];
  					return;
  				}

  				accumulator[key] = [].concat(accumulator[key], value);
  			};

  		case 'colon-list-separator':
  			return (key, value, accumulator) => {
  				result = /(:list)$/.exec(key);
  				key = key.replace(/:list$/, '');

  				if (!result) {
  					accumulator[key] = value;
  					return;
  				}

  				if (accumulator[key] === undefined) {
  					accumulator[key] = [value];
  					return;
  				}

  				accumulator[key] = [].concat(accumulator[key], value);
  			};

  		case 'comma':
  		case 'separator':
  			return (key, value, accumulator) => {
  				const isArray = typeof value === 'string' && value.includes(options.arrayFormatSeparator);
  				const isEncodedArray = (typeof value === 'string' && !isArray && decode(value, options).includes(options.arrayFormatSeparator));
  				value = isEncodedArray ? decode(value, options) : value;
  				const newValue = isArray || isEncodedArray ? value.split(options.arrayFormatSeparator).map(item => decode(item, options)) : value === null ? value : decode(value, options);
  				accumulator[key] = newValue;
  			};

  		case 'bracket-separator':
  			return (key, value, accumulator) => {
  				const isArray = /(\[\])$/.test(key);
  				key = key.replace(/\[\]$/, '');

  				if (!isArray) {
  					accumulator[key] = value ? decode(value, options) : value;
  					return;
  				}

  				const arrayValue = value === null ?
  					[] :
  					value.split(options.arrayFormatSeparator).map(item => decode(item, options));

  				if (accumulator[key] === undefined) {
  					accumulator[key] = arrayValue;
  					return;
  				}

  				accumulator[key] = [].concat(accumulator[key], arrayValue);
  			};

  		default:
  			return (key, value, accumulator) => {
  				if (accumulator[key] === undefined) {
  					accumulator[key] = value;
  					return;
  				}

  				accumulator[key] = [].concat(accumulator[key], value);
  			};
  	}
  }

  function validateArrayFormatSeparator(value) {
  	if (typeof value !== 'string' || value.length !== 1) {
  		throw new TypeError('arrayFormatSeparator must be single character string');
  	}
  }

  function encode(value, options) {
  	if (options.encode) {
  		return options.strict ? strictUriEncode(value) : encodeURIComponent(value);
  	}

  	return value;
  }

  function decode(value, options) {
  	if (options.decode) {
  		return decodeUriComponent(value);
  	}

  	return value;
  }

  function keysSorter(input) {
  	if (Array.isArray(input)) {
  		return input.sort();
  	}

  	if (typeof input === 'object') {
  		return keysSorter(Object.keys(input))
  			.sort((a, b) => Number(a) - Number(b))
  			.map(key => input[key]);
  	}

  	return input;
  }

  function removeHash(input) {
  	const hashStart = input.indexOf('#');
  	if (hashStart !== -1) {
  		input = input.slice(0, hashStart);
  	}

  	return input;
  }

  function getHash(url) {
  	let hash = '';
  	const hashStart = url.indexOf('#');
  	if (hashStart !== -1) {
  		hash = url.slice(hashStart);
  	}

  	return hash;
  }

  function extract(input) {
  	input = removeHash(input);
  	const queryStart = input.indexOf('?');
  	if (queryStart === -1) {
  		return '';
  	}

  	return input.slice(queryStart + 1);
  }

  function parseValue(value, options) {
  	if (options.parseNumbers && !Number.isNaN(Number(value)) && (typeof value === 'string' && value.trim() !== '')) {
  		value = Number(value);
  	} else if (options.parseBooleans && value !== null && (value.toLowerCase() === 'true' || value.toLowerCase() === 'false')) {
  		value = value.toLowerCase() === 'true';
  	}

  	return value;
  }

  function parse(query, options) {
  	options = Object.assign({
  		decode: true,
  		sort: true,
  		arrayFormat: 'none',
  		arrayFormatSeparator: ',',
  		parseNumbers: false,
  		parseBooleans: false
  	}, options);

  	validateArrayFormatSeparator(options.arrayFormatSeparator);

  	const formatter = parserForArrayFormat(options);

  	// Create an object with no prototype
  	const ret = Object.create(null);

  	if (typeof query !== 'string') {
  		return ret;
  	}

  	query = query.trim().replace(/^[?#&]/, '');

  	if (!query) {
  		return ret;
  	}

  	for (const param of query.split('&')) {
  		if (param === '') {
  			continue;
  		}

  		let [key, value] = splitOnFirst(options.decode ? param.replace(/\+/g, ' ') : param, '=');

  		// Missing `=` should be `null`:
  		// http://w3.org/TR/2012/WD-url-20120524/#collect-url-parameters
  		value = value === undefined ? null : ['comma', 'separator', 'bracket-separator'].includes(options.arrayFormat) ? value : decode(value, options);
  		formatter(decode(key, options), value, ret);
  	}

  	for (const key of Object.keys(ret)) {
  		const value = ret[key];
  		if (typeof value === 'object' && value !== null) {
  			for (const k of Object.keys(value)) {
  				value[k] = parseValue(value[k], options);
  			}
  		} else {
  			ret[key] = parseValue(value, options);
  		}
  	}

  	if (options.sort === false) {
  		return ret;
  	}

  	return (options.sort === true ? Object.keys(ret).sort() : Object.keys(ret).sort(options.sort)).reduce((result, key) => {
  		const value = ret[key];
  		if (Boolean(value) && typeof value === 'object' && !Array.isArray(value)) {
  			// Sort object keys, not values
  			result[key] = keysSorter(value);
  		} else {
  			result[key] = value;
  		}

  		return result;
  	}, Object.create(null));
  }

  exports.extract = extract;
  exports.parse = parse;

  exports.stringify = (object, options) => {
  	if (!object) {
  		return '';
  	}

  	options = Object.assign({
  		encode: true,
  		strict: true,
  		arrayFormat: 'none',
  		arrayFormatSeparator: ','
  	}, options);

  	validateArrayFormatSeparator(options.arrayFormatSeparator);

  	const shouldFilter = key => (
  		(options.skipNull && isNullOrUndefined(object[key])) ||
  		(options.skipEmptyString && object[key] === '')
  	);

  	const formatter = encoderForArrayFormat(options);

  	const objectCopy = {};

  	for (const key of Object.keys(object)) {
  		if (!shouldFilter(key)) {
  			objectCopy[key] = object[key];
  		}
  	}

  	const keys = Object.keys(objectCopy);

  	if (options.sort !== false) {
  		keys.sort(options.sort);
  	}

  	return keys.map(key => {
  		const value = object[key];

  		if (value === undefined) {
  			return '';
  		}

  		if (value === null) {
  			return encode(key, options);
  		}

  		if (Array.isArray(value)) {
  			if (value.length === 0 && options.arrayFormat === 'bracket-separator') {
  				return encode(key, options) + '[]';
  			}

  			return value
  				.reduce(formatter(key), [])
  				.join('&');
  		}

  		return encode(key, options) + '=' + encode(value, options);
  	}).filter(x => x.length > 0).join('&');
  };

  exports.parseUrl = (url, options) => {
  	options = Object.assign({
  		decode: true
  	}, options);

  	const [url_, hash] = splitOnFirst(url, '#');

  	return Object.assign(
  		{
  			url: url_.split('?')[0] || '',
  			query: parse(extract(url), options)
  		},
  		options && options.parseFragmentIdentifier && hash ? {fragmentIdentifier: decode(hash, options)} : {}
  	);
  };

  exports.stringifyUrl = (object, options) => {
  	options = Object.assign({
  		encode: true,
  		strict: true,
  		[encodeFragmentIdentifier]: true
  	}, options);

  	const url = removeHash(object.url).split('?')[0] || '';
  	const queryFromUrl = exports.extract(object.url);
  	const parsedQueryFromUrl = exports.parse(queryFromUrl, {sort: false});

  	const query = Object.assign(parsedQueryFromUrl, object.query);
  	let queryString = exports.stringify(query, options);
  	if (queryString) {
  		queryString = `?${queryString}`;
  	}

  	let hash = getHash(object.url);
  	if (object.fragmentIdentifier) {
  		hash = `#${options[encodeFragmentIdentifier] ? encode(object.fragmentIdentifier, options) : object.fragmentIdentifier}`;
  	}

  	return `${url}${queryString}${hash}`;
  };

  exports.pick = (input, filter, options) => {
  	options = Object.assign({
  		parseFragmentIdentifier: true,
  		[encodeFragmentIdentifier]: false
  	}, options);

  	const {url, query, fragmentIdentifier} = exports.parseUrl(input, options);
  	return exports.stringifyUrl({
  		url,
  		query: filterObj(query, filter),
  		fragmentIdentifier
  	}, options);
  };

  exports.exclude = (input, filter, options) => {
  	const exclusionFilter = Array.isArray(filter) ? key => !filter.includes(key) : (key, value) => !filter(key, value);

  	return exports.pick(input, exclusionFilter, options);
  };
  });

  function _arrayWithHoles(arr) {
    if (Array.isArray(arr)) return arr;
  }

  var arrayWithHoles = _arrayWithHoles;

  function _iterableToArrayLimit(arr, i) {
    if (typeof Symbol === "undefined" || !(Symbol.iterator in Object(arr))) return;
    var _arr = [];
    var _n = true;
    var _d = false;
    var _e = undefined;

    try {
      for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) {
        _arr.push(_s.value);

        if (i && _arr.length === i) break;
      }
    } catch (err) {
      _d = true;
      _e = err;
    } finally {
      try {
        if (!_n && _i["return"] != null) _i["return"]();
      } finally {
        if (_d) throw _e;
      }
    }

    return _arr;
  }

  var iterableToArrayLimit = _iterableToArrayLimit;

  function _arrayLikeToArray(arr, len) {
    if (len == null || len > arr.length) len = arr.length;

    for (var i = 0, arr2 = new Array(len); i < len; i++) {
      arr2[i] = arr[i];
    }

    return arr2;
  }

  var arrayLikeToArray = _arrayLikeToArray;

  function _unsupportedIterableToArray(o, minLen) {
    if (!o) return;
    if (typeof o === "string") return arrayLikeToArray(o, minLen);
    var n = Object.prototype.toString.call(o).slice(8, -1);
    if (n === "Object" && o.constructor) n = o.constructor.name;
    if (n === "Map" || n === "Set") return Array.from(o);
    if (n === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)) return arrayLikeToArray(o, minLen);
  }

  var unsupportedIterableToArray = _unsupportedIterableToArray;

  function _nonIterableRest() {
    throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
  }

  var nonIterableRest = _nonIterableRest;

  function _slicedToArray(arr, i) {
    return arrayWithHoles(arr) || iterableToArrayLimit(arr, i) || unsupportedIterableToArray(arr, i) || nonIterableRest();
  }

  var slicedToArray = _slicedToArray;

  function _arrayWithoutHoles(arr) {
    if (Array.isArray(arr)) return arrayLikeToArray(arr);
  }

  var arrayWithoutHoles = _arrayWithoutHoles;

  function _iterableToArray(iter) {
    if (typeof Symbol !== "undefined" && Symbol.iterator in Object(iter)) return Array.from(iter);
  }

  var iterableToArray = _iterableToArray;

  function _nonIterableSpread() {
    throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
  }

  var nonIterableSpread = _nonIterableSpread;

  function _toConsumableArray(arr) {
    return arrayWithoutHoles(arr) || iterableToArray(arr) || unsupportedIterableToArray(arr) || nonIterableSpread();
  }

  var toConsumableArray = _toConsumableArray;

  /**
   * Check if we're required to add a port number.
   *
   * @see https://url.spec.whatwg.org/#default-port
   * @param {Number|String} port Port number we need to check
   * @param {String} protocol Protocol we need to check against.
   * @returns {Boolean} Is it a default port for the given protocol
   * @api private
   */
  var requiresPort = function required(port, protocol) {
    protocol = protocol.split(':')[0];
    port = +port;

    if (!port) return false;

    switch (protocol) {
      case 'http':
      case 'ws':
      return port !== 80;

      case 'https':
      case 'wss':
      return port !== 443;

      case 'ftp':
      return port !== 21;

      case 'gopher':
      return port !== 70;

      case 'file':
      return false;
    }

    return port !== 0;
  };

  var has = Object.prototype.hasOwnProperty
    , undef;

  /**
   * Decode a URI encoded string.
   *
   * @param {String} input The URI encoded string.
   * @returns {String|Null} The decoded string.
   * @api private
   */
  function decode$1(input) {
    try {
      return decodeURIComponent(input.replace(/\+/g, ' '));
    } catch (e) {
      return null;
    }
  }

  /**
   * Attempts to encode a given input.
   *
   * @param {String} input The string that needs to be encoded.
   * @returns {String|Null} The encoded string.
   * @api private
   */
  function encode(input) {
    try {
      return encodeURIComponent(input);
    } catch (e) {
      return null;
    }
  }

  /**
   * Simple query string parser.
   *
   * @param {String} query The query string that needs to be parsed.
   * @returns {Object}
   * @api public
   */
  function querystring(query) {
    var parser = /([^=?#&]+)=?([^&]*)/g
      , result = {}
      , part;

    while (part = parser.exec(query)) {
      var key = decode$1(part[1])
        , value = decode$1(part[2]);

      //
      // Prevent overriding of existing properties. This ensures that build-in
      // methods like `toString` or __proto__ are not overriden by malicious
      // querystrings.
      //
      // In the case if failed decoding, we want to omit the key/value pairs
      // from the result.
      //
      if (key === null || value === null || key in result) continue;
      result[key] = value;
    }

    return result;
  }

  /**
   * Transform a query string to an object.
   *
   * @param {Object} obj Object that should be transformed.
   * @param {String} prefix Optional prefix.
   * @returns {String}
   * @api public
   */
  function querystringify(obj, prefix) {
    prefix = prefix || '';

    var pairs = []
      , value
      , key;

    //
    // Optionally prefix with a '?' if needed
    //
    if ('string' !== typeof prefix) prefix = '?';

    for (key in obj) {
      if (has.call(obj, key)) {
        value = obj[key];

        //
        // Edge cases where we actually want to encode the value to an empty
        // string instead of the stringified value.
        //
        if (!value && (value === null || value === undef || isNaN(value))) {
          value = '';
        }

        key = encode(key);
        value = encode(value);

        //
        // If we failed to encode the strings, we should bail out as we don't
        // want to add invalid strings to the query.
        //
        if (key === null || value === null) continue;
        pairs.push(key +'='+ value);
      }
    }

    return pairs.length ? prefix + pairs.join('&') : '';
  }

  //
  // Expose the module.
  //
  var stringify = querystringify;
  var parse = querystring;

  var querystringify_1 = {
  	stringify: stringify,
  	parse: parse
  };

  var controlOrWhitespace = /^[\x00-\x20\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/
    , CRHTLF = /[\n\r\t]/g
    , slashes = /^[A-Za-z][A-Za-z0-9+-.]*:\/\//
    , port = /:\d+$/
    , protocolre = /^([a-z][a-z0-9.+-]*:)?(\/\/)?([\\/]+)?([\S\s]*)/i
    , windowsDriveLetter = /^[a-zA-Z]:/;

  /**
   * Remove control characters and whitespace from the beginning of a string.
   *
   * @param {Object|String} str String to trim.
   * @returns {String} A new string representing `str` stripped of control
   *     characters and whitespace from its beginning.
   * @public
   */
  function trimLeft(str) {
    return (str ? str : '').toString().replace(controlOrWhitespace, '');
  }

  /**
   * These are the parse rules for the URL parser, it informs the parser
   * about:
   *
   * 0. The char it Needs to parse, if it's a string it should be done using
   *    indexOf, RegExp using exec and NaN means set as current value.
   * 1. The property we should set when parsing this value.
   * 2. Indication if it's backwards or forward parsing, when set as number it's
   *    the value of extra chars that should be split off.
   * 3. Inherit from location if non existing in the parser.
   * 4. `toLowerCase` the resulting value.
   */
  var rules = [
    ['#', 'hash'],                        // Extract from the back.
    ['?', 'query'],                       // Extract from the back.
    function sanitize(address, url) {     // Sanitize what is left of the address
      return isSpecial(url.protocol) ? address.replace(/\\/g, '/') : address;
    },
    ['/', 'pathname'],                    // Extract from the back.
    ['@', 'auth', 1],                     // Extract from the front.
    [NaN, 'host', undefined, 1, 1],       // Set left over value.
    [/:(\d*)$/, 'port', undefined, 1],    // RegExp the back.
    [NaN, 'hostname', undefined, 1, 1]    // Set left over.
  ];

  /**
   * These properties should not be copied or inherited from. This is only needed
   * for all non blob URL's as a blob URL does not include a hash, only the
   * origin.
   *
   * @type {Object}
   * @private
   */
  var ignore = { hash: 1, query: 1 };

  /**
   * The location object differs when your code is loaded through a normal page,
   * Worker or through a worker using a blob. And with the blobble begins the
   * trouble as the location object will contain the URL of the blob, not the
   * location of the page where our code is loaded in. The actual origin is
   * encoded in the `pathname` so we can thankfully generate a good "default"
   * location from it so we can generate proper relative URL's again.
   *
   * @param {Object|String} loc Optional default location object.
   * @returns {Object} lolcation object.
   * @public
   */
  function lolcation(loc) {
    var globalVar;

    if (typeof window !== 'undefined') globalVar = window;
    else if (typeof commonjsGlobal !== 'undefined') globalVar = commonjsGlobal;
    else if (typeof self !== 'undefined') globalVar = self;
    else globalVar = {};

    var location = globalVar.location || {};
    loc = loc || location;

    var finaldestination = {}
      , type = typeof loc
      , key;

    if ('blob:' === loc.protocol) {
      finaldestination = new Url(unescape(loc.pathname), {});
    } else if ('string' === type) {
      finaldestination = new Url(loc, {});
      for (key in ignore) delete finaldestination[key];
    } else if ('object' === type) {
      for (key in loc) {
        if (key in ignore) continue;
        finaldestination[key] = loc[key];
      }

      if (finaldestination.slashes === undefined) {
        finaldestination.slashes = slashes.test(loc.href);
      }
    }

    return finaldestination;
  }

  /**
   * Check whether a protocol scheme is special.
   *
   * @param {String} The protocol scheme of the URL
   * @return {Boolean} `true` if the protocol scheme is special, else `false`
   * @private
   */
  function isSpecial(scheme) {
    return (
      scheme === 'file:' ||
      scheme === 'ftp:' ||
      scheme === 'http:' ||
      scheme === 'https:' ||
      scheme === 'ws:' ||
      scheme === 'wss:'
    );
  }

  /**
   * @typedef ProtocolExtract
   * @type Object
   * @property {String} protocol Protocol matched in the URL, in lowercase.
   * @property {Boolean} slashes `true` if protocol is followed by "//", else `false`.
   * @property {String} rest Rest of the URL that is not part of the protocol.
   */

  /**
   * Extract protocol information from a URL with/without double slash ("//").
   *
   * @param {String} address URL we want to extract from.
   * @param {Object} location
   * @return {ProtocolExtract} Extracted information.
   * @private
   */
  function extractProtocol(address, location) {
    address = trimLeft(address);
    address = address.replace(CRHTLF, '');
    location = location || {};

    var match = protocolre.exec(address);
    var protocol = match[1] ? match[1].toLowerCase() : '';
    var forwardSlashes = !!match[2];
    var otherSlashes = !!match[3];
    var slashesCount = 0;
    var rest;

    if (forwardSlashes) {
      if (otherSlashes) {
        rest = match[2] + match[3] + match[4];
        slashesCount = match[2].length + match[3].length;
      } else {
        rest = match[2] + match[4];
        slashesCount = match[2].length;
      }
    } else {
      if (otherSlashes) {
        rest = match[3] + match[4];
        slashesCount = match[3].length;
      } else {
        rest = match[4];
      }
    }

    if (protocol === 'file:') {
      if (slashesCount >= 2) {
        rest = rest.slice(2);
      }
    } else if (isSpecial(protocol)) {
      rest = match[4];
    } else if (protocol) {
      if (forwardSlashes) {
        rest = rest.slice(2);
      }
    } else if (slashesCount >= 2 && isSpecial(location.protocol)) {
      rest = match[4];
    }

    return {
      protocol: protocol,
      slashes: forwardSlashes || isSpecial(protocol),
      slashesCount: slashesCount,
      rest: rest
    };
  }

  /**
   * Resolve a relative URL pathname against a base URL pathname.
   *
   * @param {String} relative Pathname of the relative URL.
   * @param {String} base Pathname of the base URL.
   * @return {String} Resolved pathname.
   * @private
   */
  function resolve(relative, base) {
    if (relative === '') return base;

    var path = (base || '/').split('/').slice(0, -1).concat(relative.split('/'))
      , i = path.length
      , last = path[i - 1]
      , unshift = false
      , up = 0;

    while (i--) {
      if (path[i] === '.') {
        path.splice(i, 1);
      } else if (path[i] === '..') {
        path.splice(i, 1);
        up++;
      } else if (up) {
        if (i === 0) unshift = true;
        path.splice(i, 1);
        up--;
      }
    }

    if (unshift) path.unshift('');
    if (last === '.' || last === '..') path.push('');

    return path.join('/');
  }

  /**
   * The actual URL instance. Instead of returning an object we've opted-in to
   * create an actual constructor as it's much more memory efficient and
   * faster and it pleases my OCD.
   *
   * It is worth noting that we should not use `URL` as class name to prevent
   * clashes with the global URL instance that got introduced in browsers.
   *
   * @constructor
   * @param {String} address URL we want to parse.
   * @param {Object|String} [location] Location defaults for relative paths.
   * @param {Boolean|Function} [parser] Parser for the query string.
   * @private
   */
  function Url(address, location, parser) {
    address = trimLeft(address);
    address = address.replace(CRHTLF, '');

    if (!(this instanceof Url)) {
      return new Url(address, location, parser);
    }

    var relative, extracted, parse, instruction, index, key
      , instructions = rules.slice()
      , type = typeof location
      , url = this
      , i = 0;

    //
    // The following if statements allows this module two have compatibility with
    // 2 different API:
    //
    // 1. Node.js's `url.parse` api which accepts a URL, boolean as arguments
    //    where the boolean indicates that the query string should also be parsed.
    //
    // 2. The `URL` interface of the browser which accepts a URL, object as
    //    arguments. The supplied object will be used as default values / fall-back
    //    for relative paths.
    //
    if ('object' !== type && 'string' !== type) {
      parser = location;
      location = null;
    }

    if (parser && 'function' !== typeof parser) parser = querystringify_1.parse;

    location = lolcation(location);

    //
    // Extract protocol information before running the instructions.
    //
    extracted = extractProtocol(address || '', location);
    relative = !extracted.protocol && !extracted.slashes;
    url.slashes = extracted.slashes || relative && location.slashes;
    url.protocol = extracted.protocol || location.protocol || '';
    address = extracted.rest;

    //
    // When the authority component is absent the URL starts with a path
    // component.
    //
    if (
      extracted.protocol === 'file:' && (
        extracted.slashesCount !== 2 || windowsDriveLetter.test(address)) ||
      (!extracted.slashes &&
        (extracted.protocol ||
          extracted.slashesCount < 2 ||
          !isSpecial(url.protocol)))
    ) {
      instructions[3] = [/(.*)/, 'pathname'];
    }

    for (; i < instructions.length; i++) {
      instruction = instructions[i];

      if (typeof instruction === 'function') {
        address = instruction(address, url);
        continue;
      }

      parse = instruction[0];
      key = instruction[1];

      if (parse !== parse) {
        url[key] = address;
      } else if ('string' === typeof parse) {
        index = parse === '@'
          ? address.lastIndexOf(parse)
          : address.indexOf(parse);

        if (~index) {
          if ('number' === typeof instruction[2]) {
            url[key] = address.slice(0, index);
            address = address.slice(index + instruction[2]);
          } else {
            url[key] = address.slice(index);
            address = address.slice(0, index);
          }
        }
      } else if ((index = parse.exec(address))) {
        url[key] = index[1];
        address = address.slice(0, index.index);
      }

      url[key] = url[key] || (
        relative && instruction[3] ? location[key] || '' : ''
      );

      //
      // Hostname, host and protocol should be lowercased so they can be used to
      // create a proper `origin`.
      //
      if (instruction[4]) url[key] = url[key].toLowerCase();
    }

    //
    // Also parse the supplied query string in to an object. If we're supplied
    // with a custom parser as function use that instead of the default build-in
    // parser.
    //
    if (parser) url.query = parser(url.query);

    //
    // If the URL is relative, resolve the pathname against the base URL.
    //
    if (
        relative
      && location.slashes
      && url.pathname.charAt(0) !== '/'
      && (url.pathname !== '' || location.pathname !== '')
    ) {
      url.pathname = resolve(url.pathname, location.pathname);
    }

    //
    // Default to a / for pathname if none exists. This normalizes the URL
    // to always have a /
    //
    if (url.pathname.charAt(0) !== '/' && isSpecial(url.protocol)) {
      url.pathname = '/' + url.pathname;
    }

    //
    // We should not add port numbers if they are already the default port number
    // for a given protocol. As the host also contains the port number we're going
    // override it with the hostname which contains no port number.
    //
    if (!requiresPort(url.port, url.protocol)) {
      url.host = url.hostname;
      url.port = '';
    }

    //
    // Parse down the `auth` for the username and password.
    //
    url.username = url.password = '';

    if (url.auth) {
      index = url.auth.indexOf(':');

      if (~index) {
        url.username = url.auth.slice(0, index);
        url.username = encodeURIComponent(decodeURIComponent(url.username));

        url.password = url.auth.slice(index + 1);
        url.password = encodeURIComponent(decodeURIComponent(url.password));
      } else {
        url.username = encodeURIComponent(decodeURIComponent(url.auth));
      }

      url.auth = url.password ? url.username +':'+ url.password : url.username;
    }

    url.origin = url.protocol !== 'file:' && isSpecial(url.protocol) && url.host
      ? url.protocol +'//'+ url.host
      : 'null';

    //
    // The href is just the compiled result.
    //
    url.href = url.toString();
  }

  /**
   * This is convenience method for changing properties in the URL instance to
   * insure that they all propagate correctly.
   *
   * @param {String} part          Property we need to adjust.
   * @param {Mixed} value          The newly assigned value.
   * @param {Boolean|Function} fn  When setting the query, it will be the function
   *                               used to parse the query.
   *                               When setting the protocol, double slash will be
   *                               removed from the final url if it is true.
   * @returns {URL} URL instance for chaining.
   * @public
   */
  function set(part, value, fn) {
    var url = this;

    switch (part) {
      case 'query':
        if ('string' === typeof value && value.length) {
          value = (fn || querystringify_1.parse)(value);
        }

        url[part] = value;
        break;

      case 'port':
        url[part] = value;

        if (!requiresPort(value, url.protocol)) {
          url.host = url.hostname;
          url[part] = '';
        } else if (value) {
          url.host = url.hostname +':'+ value;
        }

        break;

      case 'hostname':
        url[part] = value;

        if (url.port) value += ':'+ url.port;
        url.host = value;
        break;

      case 'host':
        url[part] = value;

        if (port.test(value)) {
          value = value.split(':');
          url.port = value.pop();
          url.hostname = value.join(':');
        } else {
          url.hostname = value;
          url.port = '';
        }

        break;

      case 'protocol':
        url.protocol = value.toLowerCase();
        url.slashes = !fn;
        break;

      case 'pathname':
      case 'hash':
        if (value) {
          var char = part === 'pathname' ? '/' : '#';
          url[part] = value.charAt(0) !== char ? char + value : value;
        } else {
          url[part] = value;
        }
        break;

      case 'username':
      case 'password':
        url[part] = encodeURIComponent(value);
        break;

      case 'auth':
        var index = value.indexOf(':');

        if (~index) {
          url.username = value.slice(0, index);
          url.username = encodeURIComponent(decodeURIComponent(url.username));

          url.password = value.slice(index + 1);
          url.password = encodeURIComponent(decodeURIComponent(url.password));
        } else {
          url.username = encodeURIComponent(decodeURIComponent(value));
        }
    }

    for (var i = 0; i < rules.length; i++) {
      var ins = rules[i];

      if (ins[4]) url[ins[1]] = url[ins[1]].toLowerCase();
    }

    url.auth = url.password ? url.username +':'+ url.password : url.username;

    url.origin = url.protocol !== 'file:' && isSpecial(url.protocol) && url.host
      ? url.protocol +'//'+ url.host
      : 'null';

    url.href = url.toString();

    return url;
  }

  /**
   * Transform the properties back in to a valid and full URL string.
   *
   * @param {Function} stringify Optional query stringify function.
   * @returns {String} Compiled version of the URL.
   * @public
   */
  function toString(stringify) {
    if (!stringify || 'function' !== typeof stringify) stringify = querystringify_1.stringify;

    var query
      , url = this
      , host = url.host
      , protocol = url.protocol;

    if (protocol && protocol.charAt(protocol.length - 1) !== ':') protocol += ':';

    var result =
      protocol +
      ((url.protocol && url.slashes) || isSpecial(url.protocol) ? '//' : '');

    if (url.username) {
      result += url.username;
      if (url.password) result += ':'+ url.password;
      result += '@';
    } else if (url.password) {
      result += ':'+ url.password;
      result += '@';
    } else if (
      url.protocol !== 'file:' &&
      isSpecial(url.protocol) &&
      !host &&
      url.pathname !== '/'
    ) {
      //
      // Add back the empty userinfo, otherwise the original invalid URL
      // might be transformed into a valid one with `url.pathname` as host.
      //
      result += '@';
    }

    //
    // Trailing colon is removed from `url.host` when it is parsed. If it still
    // ends with a colon, then add back the trailing colon that was removed. This
    // prevents an invalid URL from being transformed into a valid one.
    //
    if (host[host.length - 1] === ':' || (port.test(url.hostname) && !url.port)) {
      host += ':';
    }

    result += host + url.pathname;

    query = 'object' === typeof url.query ? stringify(url.query) : url.query;
    if (query) result += '?' !== query.charAt(0) ? '?'+ query : query;

    if (url.hash) result += url.hash;

    return result;
  }

  Url.prototype = { set: set, toString: toString };

  //
  // Expose the URL parser and some additional properties that might be useful for
  // others or testing.
  //
  Url.extractProtocol = extractProtocol;
  Url.location = lolcation;
  Url.trimLeft = trimLeft;
  Url.qs = querystringify_1;

  var urlParse = Url;

  var genesysCloudServiceDiscoveryWeb = createCommonjsModule(function (module, exports) {

  Object.defineProperty(exports, '__esModule', { value: true });



  function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

  var parseUrl__default = /*#__PURE__*/_interopDefaultLegacy(urlParse);

  /******************************************************************************
  Copyright (c) Microsoft Corporation.

  Permission to use, copy, modify, and/or distribute this software for any
  purpose with or without fee is hereby granted.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
  REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
  AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
  INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
  LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
  OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
  PERFORMANCE OF THIS SOFTWARE.
  ***************************************************************************** */

  var __assign = function() {
      __assign = Object.assign || function __assign(t) {
          for (var s, i = 1, n = arguments.length; i < n; i++) {
              s = arguments[i];
              for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
          }
          return t;
      };
      return __assign.apply(this, arguments);
  };

  function __spreadArray(to, from, pack) {
      if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
          if (ar || !(i in from)) {
              if (!ar) ar = Array.prototype.slice.call(from, 0, i);
              ar[i] = from[i];
          }
      }
      return to.concat(ar || Array.prototype.slice.call(from));
  }

  function assert(value, msg) {
      if (!value)
          throw new Error(msg);
  }
  function assertValidStringArray(value, valueName) {
      if (valueName === void 0) { valueName = 'value'; }
      assert(value instanceof Array, "".concat(valueName, " must be an array of strings"));
      for (var _i = 0, value_1 = value; _i < value_1.length; _i++) {
          var name_1 = value_1[_i];
          assert(typeof name_1 === "string", "Each item in ".concat(valueName, " must be a string"));
      }
  }
  function parseValidUrl(value) {
      assert(typeof value === "string", "url is not a string");
      // Explicitly pass {} as 2nd param so that `url-parse` parses the url
      // independently from the browser's current window location
      var url = parseUrl__default['default'](value, {});
      assert(url.protocol && url.hostname, "invalid url: '".concat(value, "', unable to parse hostname"));
      return url;
  }
  function assertValidEnvFilters(value) {
      assert(!!value && typeof value === "object", "Provided filters must be an object");
      var filters = value;
      if (filters.env !== undefined) {
          assert(filters.env instanceof Array, 'filters.env must be an array');
          assert(filters.env.every(function (env) { return ENVS.indexOf(env) >= 0; }), "'".concat(filters.env, "' - filters.env must be an array containing only: ").concat(ENVS.join(',')));
      }
      if (filters.status !== undefined) {
          assert(filters.status instanceof Array, 'filters.status must be an array');
          assert(filters.status.every(function (status) { return STATUSES.indexOf(status) >= 0; }), "'".concat(filters.status, "' - filters.status must be an array containing only: ").concat(STATUSES.join(',')));
      }
  }

  var _environments = [
  	{
  		name: "fedramp-use2-core",
  		env: "fedramp",
  		region: "us-east-2",
  		status: "stable",
  		publicDomainName: "use2.us-gov-pure.cloud",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod",
  		env: "prod",
  		region: "us-east-1",
  		status: "stable",
  		publicDomainName: "mypurecloud.com",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-apne1",
  		env: "prod",
  		region: "ap-northeast-1",
  		status: "stable",
  		publicDomainName: "mypurecloud.jp",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-apne2",
  		env: "prod",
  		region: "ap-northeast-2",
  		status: "stable",
  		publicDomainName: "apne2.pure.cloud",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-apne3",
  		env: "prod",
  		region: "ap-northeast-3",
  		status: "stable",
  		publicDomainName: "apne3.pure.cloud",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-aps1",
  		env: "prod",
  		region: "ap-south-1",
  		status: "stable",
  		publicDomainName: "aps1.pure.cloud",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-apse2",
  		env: "prod",
  		region: "ap-southeast-2",
  		status: "stable",
  		publicDomainName: "mypurecloud.com.au",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-cac1",
  		env: "prod",
  		region: "ca-central-1",
  		status: "stable",
  		publicDomainName: "cac1.pure.cloud",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-euc1",
  		env: "prod",
  		region: "eu-central-1",
  		status: "stable",
  		publicDomainName: "mypurecloud.de",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-euc2",
  		env: "prod",
  		region: "eu-central-2",
  		status: "stable",
  		publicDomainName: "euc2.pure.cloud",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-euw1",
  		env: "prod",
  		region: "eu-west-1",
  		status: "stable",
  		publicDomainName: "mypurecloud.ie",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-euw2",
  		env: "prod",
  		region: "eu-west-2",
  		status: "stable",
  		publicDomainName: "euw2.pure.cloud",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-mec1",
  		env: "prod",
  		region: "me-central-1",
  		status: "stable",
  		publicDomainName: "mec1.pure.cloud",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-sae1",
  		env: "prod",
  		region: "sa-east-1",
  		status: "stable",
  		publicDomainName: "sae1.pure.cloud",
  		publicDomainAliases: [
  		]
  	},
  	{
  		name: "prod-usw2",
  		env: "prod",
  		region: "us-west-2",
  		status: "stable",
  		publicDomainName: "usw2.pure.cloud",
  		publicDomainAliases: [
  		]
  	}
  ];

  var environments = _environments;
  var ENVS = ["dev", "test", "prod", "fedramp"];
  var STATUSES = ["alpha", "beta", "stable", "archived"];
  var DEFAULT_LOCAL_HOSTNAMES = ["localhost", "127.0.0.1"];
  var STABLE_PUBLIC_ENVS_FILTERS = { env: ["prod", "fedramp"], status: ["stable"] };
  var NO_FILTERS = {};
  var endsWith = function (s1, s2) {
      return s1.slice(s1.length - s2.length) === s2;
  };
  var matchesHostname = function (hostname) { return function (domain) {
      return hostname === domain || endsWith(hostname, ".".concat(domain));
  }; };
  /**
   * Retrieves the list of Genesys Cloud environment/region deployments.
   * Defaults to only returning stable, publically available deployments (e.g. prod, fedramp)
   */
  var getEnvironments = function (filters) {
      if (filters === void 0) { filters = STABLE_PUBLIC_ENVS_FILTERS; }
      assertValidEnvFilters(filters);
      var env = filters.env, status = filters.status;
      return environments
          .filter(function (data) { return env === undefined || env.indexOf(data.env) >= 0; })
          .filter(function (data) { return status === undefined || status.indexOf(data.status) >= 0; });
  };
  /**
   * Whether or not the given url is a known Genesys Cloud deployment.  If no filters
   * are provided, the default behavior is to only check stable, publically available deployments
   * (e.g. prod, fedramp).
   *
   * - throws an error if passed an invalid url
   * - returns false for localhost
   */
  var isKnown = function (url, filters) { return !!parse(url, filters); };
  /**
   * Retrieve the Genesys Cloud `Environment` for a given url.  If no filters
   * are provided, the default behavior is to only check stable, publically available deployments
   * (e.g. prod, fedramp).
   *
   * - throws an error if passed an invalid url
   * - returns undefined if no match is found
   */
  var parse = function (url, filters) {
      var hostname = parseValidUrl(url).hostname;
      return getEnvironments(filters).find(function (_a) {
          var publicDomainName = _a.publicDomainName, publicDomainAliases = _a.publicDomainAliases;
          var domains = __spreadArray([publicDomainName], publicDomainAliases, true).filter(function (d) { return !!d; });
          return domains.some(matchesHostname(hostname));
      });
  };
  /**
   * Retrieve the current Genesys Cloud runtime environment for the given url.
   * This method attempts to parse the hostname directly (uses `parse` under the hood).
   *
   * By default, this method will attempt to search across all available environments (no filtering).
   */
  var parseDeployedRuntime = function (url, filters) {
      if (url === void 0) { url = window.location.href; }
      if (filters === void 0) { filters = NO_FILTERS; }
      assertValidEnvFilters(filters);
      var hostname = parseValidUrl(url).hostname;
      var parsedEnv = parse(url, filters);
      if (!parsedEnv)
          return;
      return __assign(__assign({}, parsedEnv), { local: false, currentDomainName: __spreadArray([
              parsedEnv.publicDomainName
          ], parsedEnv.publicDomainAliases, true).filter(function (d) { return !!d; }).find(matchesHostname(hostname)) });
  };
  /**
   * When the hostname matches a valid local hostname, either by matching our defaults or your custom list
   * passed in the options, this method will attempt to match the first path param by name to an environment.
   * The list of environment names can be retrieved by calling `getEnvironments` and can be found under the
   * `name` key.
   *
   * By default, this method will attempt to search across all available environments (no filtering).
   *
   * Note: `currentDomainName` will be equal to `publicDomainName` when using this method.
   * Example: https://localhost:3000/prod => us-east-1 prod environment & runtime details
   */
  var parseRuntimeFromLocalPath = function (localHostnames) {
      if (localHostnames === void 0) { localHostnames = DEFAULT_LOCAL_HOSTNAMES; }
      return function (url, filters) {
          if (url === void 0) { url = window.location.href; }
          if (filters === void 0) { filters = NO_FILTERS; }
          assertValidEnvFilters(filters);
          assertValidStringArray(localHostnames, 'localHostnames');
          var _a = parseValidUrl(url), hostname = _a.hostname, pathname = _a.pathname;
          if (localHostnames.indexOf(hostname) >= 0) {
              var _b = pathname.split("/"), envName_1 = _b[1];
              var localEnv = getEnvironments(filters).find(function (e) { return e.name === envName_1; });
              if (!localEnv)
                  return;
              return __assign(__assign({}, localEnv), { local: true, currentDomainName: localEnv.publicDomainName });
          }
      };
  };
  /**
   * This is the default and recommended `RuntimeParser` implementation that is composed of the
   * `parseDeployedRuntime` and `parseRuntimeFromLocalPath` parsers. You might opt to compose the
   * `parseDeployedRuntime` with your own `RuntimeParser` as an alternative to parseRuntimeFromLocalPath.
   * You may also opt to use "parse" and `getEnvironments` together to create your own parsing strategy.
   */
  var parseRuntime = function (url, filters) {
      if (url === void 0) { url = window.location.href; }
      if (filters === void 0) { filters = NO_FILTERS; }
      return parseRuntimeFromLocalPath()(url, filters) || parseDeployedRuntime(url, filters);
  };

  exports.ENVS = ENVS;
  exports.STATUSES = STATUSES;
  exports.getEnvironments = getEnvironments;
  exports.isKnown = isKnown;
  exports.parse = parse;
  exports.parseDeployedRuntime = parseDeployedRuntime;
  exports.parseRuntime = parseRuntime;
  exports.parseRuntimeFromLocalPath = parseRuntimeFromLocalPath;
  });

  var index = /*@__PURE__*/unwrapExports(genesysCloudServiceDiscoveryWeb);

  var buildPcEnv = function buildPcEnv(tld) {
    return {
      pcEnvTld: tld,
      pcAppOrigin: "https://apps.".concat(tld)
    };
  };

  var DEFAULT_ENV_REGION = 'us-east-1';
  var environments = index.getEnvironments({
    env: ['prod', 'fedramp'],
    status: ['beta', 'stable']
  });
  var PC_ENV_TLDS = environments.reduce(function (tlds, env) {
    tlds.push(env.publicDomainName);
    tlds.push.apply(tlds, toConsumableArray(env.publicDomainAliases));
    return tlds;
  }, []).concat([]);

  var _environments$filter = environments.filter(function (env) {
    return env.region === DEFAULT_ENV_REGION;
  }),
      _environments$filter2 = slicedToArray(_environments$filter, 1),
      defaultEnv = _environments$filter2[0];

  var DEFAULT_PC_ENV = buildPcEnv(defaultEnv.publicDomainName);

  function isKnownEnvName(toCheck, envs) {
    var envList = new Set([].concat(toConsumableArray(envs), []).map(function (e) {
      return e.name;
    }));
    return envList.has(toCheck);
  }

  var matchesHostname = function matchesHostname(hostname) {
    return function (domain) {
      return hostname === domain || hostname.endsWith(".".concat(domain));
    };
  };

  function findPcEnvironment(location, targetEnv, envs) {
    var parsedEnv = [].concat(toConsumableArray(envs), []).find(function (_ref) {
      var publicDomainName = _ref.publicDomainName,
          publicDomainAliases = _ref.publicDomainAliases;
      var domains = [publicDomainName].concat(toConsumableArray(publicDomainAliases)).filter(function (d) {
        return !!d;
      });
      return domains.some(matchesHostname(location.hostname));
    });

    if (parsedEnv && parsedEnv.name === targetEnv) {
      return {
        pcEnvTld: parsedEnv.publicDomainName,
        pcAppOrigin: location.origin
      };
    }

    return null;
  }
  /**
   * Attempts to locate a PC environment corresponding to the provided search params
   *
   * @param pcEnvTld A string representing the Genesys Cloud environment top-level domain to search for
   * @param lenient When true, trims leading/trailing whitespace, ignores leading '.', and ignores trailing '/'.
   * @param envTlds A string array of all available Genesys Cloud environment top-level domains
   * @param hostAppDevOrigin The origin to target when the host app is running on `localhost`
   *
   * @returns A Genesys Cloud environment object if found; null otherwise.
   */


  var lookupPcEnv = function lookupPcEnv(pcEnvTld) {
    var lenient = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
    var envTlds = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : PC_ENV_TLDS;
    var hostAppDevOrigin = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : undefined;

    if (pcEnvTld && typeof pcEnvTld === 'string') {
      if (pcEnvTld === 'localhost' && hostAppDevOrigin) {
        return {
          pcEnvTld: 'localhost',
          pcAppOrigin: hostAppDevOrigin
        };
      }

      var toSearch = pcEnvTld;

      if (lenient) {
        toSearch = toSearch.trim();

        if (toSearch.indexOf('.') === 0) {
          toSearch = toSearch.substring(1);
        }

        if (toSearch.indexOf('/') === toSearch.length - 1) {
          toSearch = toSearch.substring(0, toSearch.length - 1);
        }
      }

      if (envTlds.indexOf(toSearch) >= 0) {
        return buildPcEnv(toSearch);
      }
    }

    return null;
  };
  /**
   * Attempts to locate a GC environment corresponding to the provided origin/targetEnv combination
   * @param url A string representing the Genesys Cloud environment url
   * @param targetEnv A string representing the Genesys Cloud environment target
   * @param envs A Environment array of all available Genesys Cloud environments
   * @returns A Genesys Cloud environment object if found; null otherwise.
   */

  var lookupGcEnv = function lookupGcEnv(url, targetEnv) {
    var envs = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : environments;

    if (!isKnownEnvName(targetEnv, envs)) {
      return null;
    }

    try {
      var hostLocation = new URL(url);

      if (['localhost', '127.0.0.1'].includes(hostLocation.hostname)) {
        return {
          pcEnvTld: 'localhost',
          pcAppOrigin: hostLocation.origin
        };
      } else {
        return findPcEnvironment(hostLocation, targetEnv, envs);
      }
    } catch (_unused) {
      return null;
    }
  };

  var _extends_1 = createCommonjsModule(function (module) {
  function _extends() {
    module.exports = _extends = Object.assign || function (target) {
      for (var i = 1; i < arguments.length; i++) {
        var source = arguments[i];

        for (var key in source) {
          if (Object.prototype.hasOwnProperty.call(source, key)) {
            target[key] = source[key];
          }
        }
      }

      return target;
    };

    return _extends.apply(this, arguments);
  }

  module.exports = _extends;
  });

  var _typeof_1 = createCommonjsModule(function (module) {
  function _typeof(obj) {
    "@babel/helpers - typeof";

    if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") {
      module.exports = _typeof = function _typeof(obj) {
        return typeof obj;
      };
    } else {
      module.exports = _typeof = function _typeof(obj) {
        return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj;
      };
    }

    return _typeof(obj);
  }

  module.exports = _typeof;
  });

  var getPrototypeOf = createCommonjsModule(function (module) {
  function _getPrototypeOf(o) {
    module.exports = _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf : function _getPrototypeOf(o) {
      return o.__proto__ || Object.getPrototypeOf(o);
    };
    return _getPrototypeOf(o);
  }

  module.exports = _getPrototypeOf;
  });

  function _superPropBase(object, property) {
    while (!Object.prototype.hasOwnProperty.call(object, property)) {
      object = getPrototypeOf(object);
      if (object === null) break;
    }

    return object;
  }

  var superPropBase = _superPropBase;

  var get = createCommonjsModule(function (module) {
  function _get(target, property, receiver) {
    if (typeof Reflect !== "undefined" && Reflect.get) {
      module.exports = _get = Reflect.get;
    } else {
      module.exports = _get = function _get(target, property, receiver) {
        var base = superPropBase(target, property);
        if (!base) return;
        var desc = Object.getOwnPropertyDescriptor(base, property);

        if (desc.get) {
          return desc.get.call(receiver);
        }

        return desc.value;
      };
    }

    return _get(target, property, receiver || target);
  }

  module.exports = _get;
  });

  var setPrototypeOf = createCommonjsModule(function (module) {
  function _setPrototypeOf(o, p) {
    module.exports = _setPrototypeOf = Object.setPrototypeOf || function _setPrototypeOf(o, p) {
      o.__proto__ = p;
      return o;
    };

    return _setPrototypeOf(o, p);
  }

  module.exports = _setPrototypeOf;
  });

  function _inherits(subClass, superClass) {
    if (typeof superClass !== "function" && superClass !== null) {
      throw new TypeError("Super expression must either be null or a function");
    }

    subClass.prototype = Object.create(superClass && superClass.prototype, {
      constructor: {
        value: subClass,
        writable: true,
        configurable: true
      }
    });
    if (superClass) setPrototypeOf(subClass, superClass);
  }

  var inherits = _inherits;

  function _assertThisInitialized(self) {
    if (self === void 0) {
      throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
    }

    return self;
  }

  var assertThisInitialized = _assertThisInitialized;

  function _possibleConstructorReturn(self, call) {
    if (call && (_typeof_1(call) === "object" || typeof call === "function")) {
      return call;
    }

    return assertThisInitialized(self);
  }

  var possibleConstructorReturn = _possibleConstructorReturn;

  var commsUtils = {
    /**
     * Posts the provided msg to the specified origin and parent window when invoked within the
     * expected environment (e.g. a frame hosted within Genesys Cloud).
     *
     * @param msg - The payload to send as a postMessage
     * @param tgtOrigin - The destination origin (see postMessage)
     * @param transfer - Transferable objects (see postMessage)
     * @param myWindow - The current execution window. Default window
     * @param myParent - The parent window to which the message should be posted. Default parent
     * @param myConsole - logs errors here rather than throwing errors. Default console
     *
     * @throws Error if the environment is invalid (e.g. not a browser, no postMessage api,
     *  not running within an iframe) and myConsole is not specified
     */
    postMsgToPc: function postMsgToPc(msg, tgtOrigin, transfer) {
      var myWindow = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : window;
      var myParent = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : window.parent;
      var myConsole = arguments.length > 5 && arguments[5] !== undefined ? arguments[5] : window.console;
      var validRuntime = !!(myWindow && _typeof_1(myWindow) === 'object' && myParent && _typeof_1(myParent) === 'object');
      var validEnv = validRuntime && myParent !== myWindow;
      var validApi = !!(myParent && typeof myParent.postMessage === 'function');

      if (validRuntime && validEnv && validApi) {
        myParent.postMessage(msg, tgtOrigin, transfer);
      } else {
        var errMsg = 'PureCloud Communication Failed.  ';

        if (!validRuntime) {
          errMsg += 'Not running within a browser.';
        } else if (!validEnv) {
          errMsg += 'Not running within an iframe.';
        } else {
          errMsg += 'postMessage not supported in this browser.';
        }

        if (myConsole) {
          myConsole.error(errMsg);
        } else {
          throw new Error(errMsg);
        }
      }
    }
  };

  var PROTOCOL_NAME = 'purecloud-client-apps';

  /**
   * Base Class for Genesys Cloud Client App APIs
   *
   * @since 1.0.0
   */
  var BaseApi = /*#__PURE__*/function () {
    // ----- Message Listening

    /**
     * Injection point for tests.  Should not be used by api users or extenders.
     */

    /**
     * Injection point for tests.  Should not be used by api users or extenders.
     */

    /**
     * Injection point for tests.  Should not be used by api users or extenders.
     */

    /**
     * Instantiates the BaseApi
     *
     * @param cfg Optional configuration
     *
     * @since 1.0.0
     */
    function BaseApi() {
      var _this = this;

      var cfg = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

      classCallCheck(this, BaseApi);

      defineProperty(this, "_targetPcOrigin", void 0);

      defineProperty(this, "_protocolDetails", void 0);

      defineProperty(this, "_msgListenerCfgs", {});

      defineProperty(this, "_msgHandler", function (event) {
        return _this._onMsg(event);
      });

      defineProperty(this, "_commsUtils", commsUtils);

      defineProperty(this, "_myWindow", window);

      defineProperty(this, "_myParent", window ? window.parent : undefined);

      this._targetPcOrigin = cfg.targetPcOrigin || '*';
      this._protocolDetails = {
        name: cfg.protocol || PROTOCOL_NAME,
        agentName: cfg.protocolAgentName || "purecloud-client-app-sdk",
        agentVersion: cfg.protocolAgentVersion || "2.6.6"
      };
    }
    /**
     * Sends the message to Genesys Cloud augmenting with environmental details such as
     * target env origin and version info.  Accessible by extenders.
     *
     * @param actionName
     * @param msgPayload
     *
     * @since 1.0.0
     */


    createClass(BaseApi, [{
      key: "sendMsgToPc",
      value: function sendMsgToPc(actionName, msgPayload) {
        this._commsUtils.postMsgToPc(this.buildSdkMsgPayload(actionName, msgPayload), this._targetPcOrigin);
      }
      /**
       * Constructs a payload tailored for the Genesys Cloud Client Apps SDK.  Can be
       * overridden by extenders, but should not be invoked externally.
       *
       * @param actionName - The name of the client-app action to invoke
       * @param msgPayload - Action-specific payload data
       *
       * @returns A postMessage payload for the Client Apps SDK
       *
       * @since 1.0.0
       */

    }, {
      key: "buildSdkMsgPayload",
      value: function buildSdkMsgPayload(actionName, msgPayload) {
        var result = {}; // Clone the payload

        if (msgPayload && _typeof_1(msgPayload) === 'object') {
          result = JSON.parse(JSON.stringify(msgPayload));
        }

        result.action = actionName;
        result.protocol = this._protocolDetails.name;
        result.protocolAgentName = this._protocolDetails.agentName;
        result.protocolAgentVersion = this._protocolDetails.agentVersion;
        return result;
      } // ----- Message Listening

      /**
       * Adds the specified listener to messages sent from the host Genesys Cloud appliation
       * on the specified eventType
       *
       * @param eventType - The name of the purecloudEventType in the message; case and leading/trailing space sensitive
       * @param listener - The listener function to invoke when a message of the specified eventType
       *   is received.  Message data will be passed
       * @param options - Options for the invocation of the listener; null/undefined will use defaults
       *
       * @since 1.0.0
       */

    }, {
      key: "addMsgListener",
      value: function addMsgListener(eventType, listener) {
        var _this2 = this;

        var options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};

        if (!eventType || typeof eventType !== 'string' || eventType.trim().length === 0) {
          throw new Error('Invalid eventType provided to addMsgListener');
        }

        if (!listener || typeof listener !== 'function') {
          throw new Error('Invalid listener provided to addMsgListener');
        }

        var proposedListenerCfg = {
          listener: listener,
          options: this._buildNormalizedListenerOptions(options)
        };
        var duplicateListener = false;
        var listenerCfgs = this._msgListenerCfgs[eventType];

        if (!listenerCfgs) {
          listenerCfgs = [];
          this._msgListenerCfgs[eventType] = listenerCfgs;
        } else if (listenerCfgs.length > 0) {
          // Check for duplicates
          listenerCfgs.forEach(function (currListenerCfg) {
            if (_this2._isDuplicateListenerCfg(currListenerCfg, proposedListenerCfg)) {
              duplicateListener = true;
            }
          });
        }

        if (!duplicateListener) {
          listenerCfgs.push(proposedListenerCfg);

          if (this._getListenerCount() === 1) {
            // This is the addition of the only active listener, start listening
            this._subscribeToMsgs();
          }
        }
      }
      /**
       * Removes the specified listener from messages sent from the host Genesys Cloud appliation
       * on the specified eventType. eventType, listener (strict equality), and options must match.
       *
       * @param eventType - The name of the purecloudEventType previously registered; case and leading/trailing space sensitive
       * @param listener - The exact listener function instance that was previously registered.
       * @param options - Options registered with the listener;
       *  null and undefined trigger defaults and will be considered equal.
       *
       * @throws Error if the eventType, listener, or options are invalid
       *
       * @since 1.0.0
       */

    }, {
      key: "removeMsgListener",
      value: function removeMsgListener(eventType, listener) {
        var options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};

        if (!eventType || typeof eventType !== 'string' || eventType.trim().length === 0) {
          throw new Error('Invalid eventType provided to removeMsgListener');
        }

        if (!listener || typeof listener !== 'function') {
          throw new Error('Invalid listener provided to removeMsgListener');
        } // Note: Building the normalized options also validates the options param.
        // This should stay here to always validate the params regardless of eventType listener presence


        var listenerCfgToRemove = {
          listener: listener,
          options: this._buildNormalizedListenerOptions(options)
        };
        var eventTypeListenerCfgs = this._msgListenerCfgs[eventType];

        if (eventTypeListenerCfgs) {
          var listenerCfgIndex = -1;

          for (var index = 0; index < eventTypeListenerCfgs.length; index++) {
            if (this._isDuplicateListenerCfg(eventTypeListenerCfgs[index], listenerCfgToRemove)) {
              listenerCfgIndex = index;
              break;
            }
          }

          if (listenerCfgIndex >= 0) {
            eventTypeListenerCfgs.splice(listenerCfgIndex, 1);

            if (this._getListenerCount() === 0) {
              // No more listeners, tear down our listener
              this._unsubscribeFromMsgs();
            }
          }
        }
      }
      /**
       * Returns the total number of registered listeners.
       */

    }, {
      key: "_getListenerCount",
      value: function _getListenerCount() {
        var _this3 = this;

        var result = 0;
        Object.keys(this._msgListenerCfgs).forEach(function (currEventType) {
          var currListenerCfgs = _this3._msgListenerCfgs[currEventType];

          if (currListenerCfgs) {
            result += currListenerCfgs.length;
          }
        });
        return result;
      }
      /**
       * Initiate listening for messages from the host Genesys Cloud application
       */

    }, {
      key: "_subscribeToMsgs",
      value: function _subscribeToMsgs() {
        this._myWindow.addEventListener('message', this._msgHandler);
      }
      /**
       * Stop listening for messages from the host Genesys Cloud application
       */

    }, {
      key: "_unsubscribeFromMsgs",
      value: function _unsubscribeFromMsgs() {
        this._myWindow.removeEventListener('message', this._msgHandler);
      }
      /**
       * Message handler function that will filter message events and invoke the correct, registered
       * listeners.
       */

    }, {
      key: "_onMsg",
      value: function _onMsg(event) {
        var _this4 = this;

        if (!event || !event.source || !event.origin || event.source !== this._myParent || event.origin !== this._targetPcOrigin || !event.data || _typeof_1(event.data) !== 'object' || Array.isArray(event.data)) {
          // Fast-fail for invalid or unknown event
          return;
        } // Validate base payload


        var eventType = event.data.purecloudEventType;

        if (eventType && typeof eventType === 'string' && eventType.trim()) {
          var eventTypeListenerCfgs = this._msgListenerCfgs[eventType];

          if (eventTypeListenerCfgs && eventTypeListenerCfgs.length > 0) {
            var listenerCfgsToRemove = [];
            eventTypeListenerCfgs.forEach(function (currListenerCfg) {
              if (!currListenerCfg.options.msgPayloadFilter || currListenerCfg.options.msgPayloadFilter(event.data)) {
                // Clone the event data and prune internal props before sending the event to user-space
                var userSpaceEventData = JSON.parse(JSON.stringify(event.data));
                delete userSpaceEventData.protocol;
                currListenerCfg.listener(userSpaceEventData);

                if (currListenerCfg.options.once) {
                  listenerCfgsToRemove.push(currListenerCfg);
                }
              }
            });

            if (listenerCfgsToRemove.length > 0) {
              listenerCfgsToRemove.forEach(function (currListenerCfg) {
                _this4.removeMsgListener(eventType, currListenerCfg.listener, currListenerCfg.options);
              });
            }
          }
        }
      }
      /**
       * Validates and normalizes listener options. msgPayloadFilter will be normalized to null and once
       * will be normalized to false if not specified or specified as an "empty" object (null/undefined).
       *
       * @param options The additional options config provided to [add|remove]MsgListener; null and undefined also allowed.
       *
       * @returns A normalized listener options object containing the msgPayloadFilter and once properties.
       * msgPayloadFilter will be null unless a valid function is explicitly provided.  once will be false unless true
       * is explictly provided.
       *
       * @throws Error if options is not null, undefined, or an object
       * @throws Error if options.msgPayloadFilter is not null, undefined, or a function
       * @throws Error if options.once is not null, undefined, or a boolean
       */

    }, {
      key: "_buildNormalizedListenerOptions",
      value: function _buildNormalizedListenerOptions(options) {
        var result = {
          msgPayloadFilter: null,
          once: false
        };

        if (options === null || options === undefined) {
          return result;
        }

        if (_typeof_1(options) !== 'object' || Array.isArray(options)) {
          throw new Error('Invalid options provided');
        }

        var filter = options.msgPayloadFilter;

        if (filter !== null && filter !== undefined && typeof filter !== 'function') {
          throw new Error('options.msgPayloadFilter must be a function if specified');
        }

        result.msgPayloadFilter = filter || null;

        if (options.once !== null && options.once !== undefined && typeof options.once !== 'boolean') {
          throw new Error('options.once must be a boolean if specified');
        }

        result.once = options.once || false;
        return result;
      }
      /**
       * Determines if the specified listener configs are duplicates with respect to
       * listener registration.  Assumes the configs will be normalized for easier comparison.
       *
       * @param listenerCfg1 The first config
       * @param listenerCfg2 The second config
       *
       * @returns true if the listener, msgPayloadFilter, and once are equal; false otherwise
       */

    }, {
      key: "_isDuplicateListenerCfg",
      value: function _isDuplicateListenerCfg(listenerCfg1, listenerCfg2) {
        return listenerCfg1.listener === listenerCfg2.listener && listenerCfg1.options.once === listenerCfg2.options.once && listenerCfg1.options.msgPayloadFilter === listenerCfg2.options.msgPayloadFilter;
      }
    }]);

    return BaseApi;
  }();

  function _createSuper(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct(); return function _createSuperInternal() { var Super = getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return possibleConstructorReturn(this, result); }; }

  function _isNativeReflectConstruct() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }
  var VALID_MESSAGE_TYPES = ['error', 'info', 'success'];
  var VALID_SUPPLEMENTAL_OPTIONS = ['id', 'markdownMessage', 'timeout', 'showCloseButton'];

  var isValidMessageType = function isValidMessageType(type) {
    return VALID_MESSAGE_TYPES.indexOf(type) > -1;
  };

  var pick = function pick(obj, keys) {
    var newObj = {};
    keys.forEach(function (key) {
      newObj[key] = obj[key];
    });
    return newObj;
  };

  var defaultToastOptions = {
    type: 'info',
    timeout: 7,
    showCloseButton: true,
    markdownMessage: true
  };
  /**
   * Handles aspects of alerting and attention of this app with Genesys Cloud
   *
   * @noInheritDoc
   * @since 1.0.0
   */

  var AlertingApi = /*#__PURE__*/function (_BaseApi) {
    inherits(AlertingApi, _BaseApi);

    var _super = _createSuper(AlertingApi);

    function AlertingApi() {
      classCallCheck(this, AlertingApi);

      return _super.apply(this, arguments);
    }

    createClass(AlertingApi, [{
      key: "showToastPopup",

      /**
       * Displays a toast popup.
       *
       * Permanent/Sticky toasts are not allowed.  Therefore, toasts must specify either a manual
       * dismissal (`showCloseButton: true`) or an automatic dismissal (`timeout > 0`). Both
       * `showCloseButton` and `timeout` can be specified to provide both dismissal options.
       *
       * Error toasts (`type: 'error'`) require manual dismissal and must be explictly specified with `showCloseButton: true`.
       * TypeScript users will also specify `timeout: 0` while JavaScript users can specify 0 or omit the prop entirely.
       * The `timeout` prop will be ignored regardless.
       * 
       * **Toast Options:**
       * 
       * Name | Type | Default | Description |
       * `id` | string | your app's namespace | The id of the message.  Duplicate IDs will replace each other in the toast display.  All IDs will be namespaced with your app ID to avoid collisions. Default will just be your app's namespace and will not support multiple messages. |
       * `type` | 'error' &#124; 'info' &#124; 'success' | 'info' | The type of the toast message. |
       * `markdownMessage` |  boolean | true | Indicates if the message is in MD. |
       * `timeout` | number | 7 | Time in seconds to show the toast.  Set to `0` to disable automatic dismissal. `timeout` must be `0` for toasts with `type: 'error'`. |
       * `showCloseButton` | boolean | true | Indicates if the close button should be shown. Must be explicitly set to true when `timeout` is `0`. |
       * 
       * The type parameters impact the options config. The `MessageType` type extends `'error' | 'info' | 'success'`, and when it is set to `'error'`, it enforces that `timeout` is `0`. The `Timeout` type extends `number`, and when set to `0` it enforces that `showCloseButton` is `true` to prevent a permanent toast message.
       *
       * ```ts
       * myClientApp.alerting.showToastPopup("Hello world", "Hello world, how are you doing today?");
       * ```
       *
       * ```ts
       * var options = {
       *    type: 'success'
       * };
       * myClientApp.alerting.showToastPopup("Hello world", "Hello world, how are you doing today?", options);
       * ```
       *
       * ```ts
       * var options = {
       *    id: 'greeting',
       *    timeout: 0,
       *    showCloseButton: true
       * };
       * myClientApp.alerting.showToastPopup("Hello world", "Hello world, how are you doing today?", options);
       * // Set new id so the messages can show together
       * options.id = 'exit'
       * myClientApp.alerting.showToastPopup("Goodbye world", "See you later world", options);
       * ```
       *
       * ```ts
       * var options = {
       *    id: 'mdExample',
       *    markdownMessage: true
       * };
       * myClientApp.alerting.showToastPopup("Hello world", "Hello :earth_americas: How are *you* doing today?", options);
       * ```
       * 
       * @param title - Toast title.
       * @param message - Toast Message.  Supports emoticons, emoji (unicode, shortcodes) and markdown (with markdownMessage boolean).
       * @param options - Additonal toast options. 
       *
       * @since 1.0.0
       */
      value: function showToastPopup(title, message, options) {
        var toastOptions = options || defaultToastOptions;
        var messageParams = {
          title: title,
          message: message,
          type: 'info'
        };

        if (toastOptions && _typeof_1(toastOptions) === 'object') {
          if (toastOptions.type && typeof toastOptions.type === 'string') {
            var requestedType = toastOptions.type.trim().toLowerCase();

            if (isValidMessageType(requestedType)) {
              messageParams.type = requestedType;
            }
          }

          var validOptions = pick(toastOptions, VALID_SUPPLEMENTAL_OPTIONS);

          _extends_1(messageParams, validOptions);
        }

        get(getPrototypeOf(AlertingApi.prototype), "sendMsgToPc", this).call(this, 'showToast', messageParams);
      }
      /**
       * Displays badging for unread messages and notifications
       *
       * ```ts
       * myClientApp.alerting.setAttentionCount(2);
       * ```
       *
       * ```ts
       * myClientApp.alerting.setAttentionCount(0);
       * ```
       *
       * @param count - The updated number of unread messages or notifications
       *
       * @since 1.0.0
       */

    }, {
      key: "setAttentionCount",
      value: function setAttentionCount(count) {
        get(getPrototypeOf(AlertingApi.prototype), "sendMsgToPc", this).call(this, 'setAttentionCount', {
          count: count
        });
      }
    }]);

    return AlertingApi;
  }(BaseApi);

  function _createSuper$1(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct$1(); return function _createSuperInternal() { var Super = getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return possibleConstructorReturn(this, result); }; }

  function _isNativeReflectConstruct$1() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }
  var LIFECYCLE_HOOK_EVENT_NAME = 'appLifecycleHook';

  var buildHookFilter = function buildHookFilter(hookName) {
    return function (msgPayload) {
      return _typeof_1(msgPayload) === 'object' && msgPayload.hook === hookName;
    };
  };

  var BOOTSTRAP_HOOK_FILTER = buildHookFilter('bootstrap');
  var FOCUS_HOOK_FILTER = buildHookFilter('focus');
  var BLUR_HOOK_FILTER = buildHookFilter('blur');
  var STOP_HOOK_FILTER = buildHookFilter('stop');
  /**
   * Utilities for monitoring and updating the lifecycle of a Genesys Cloud Client App
   *
   * ### Lifecycle Hooks
   *
   * These utilities require the app to be opted into the appropriate lifecycle hook via
   * advanced configuration.  This can be set via the API, Admin UI, or hard-coded for Premium Apps.
   * The format of lifecycle hooks in advanced configuration is as follows:
   *
   * ```json
   * {
   *   "lifecycle": {
   *     "ephemeral": <boolean>,
   *     "hooks": {
   *       "stop": <boolean>,
   *       "blur": <boolean>,
   *       "focus": <boolean>,
   *       "bootstrap": <boolean>
   *     }
   *   }
   * }
   * ```
   *
   * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events) for more details
   * @noInheritDoc
   * @since 1.0.0
   */

  var LifecycleApi = /*#__PURE__*/function (_BaseApi) {
    inherits(LifecycleApi, _BaseApi);

    var _super = _createSuper$1(LifecycleApi);

    function LifecycleApi() {
      classCallCheck(this, LifecycleApi);

      return _super.apply(this, arguments);
    }

    createClass(LifecycleApi, [{
      key: "addBootstrapListener",

      /**
       * Attach a listener function to be called when Genesys Cloud has loaded the app.
       *
       * This provides a hook for implementers to do any post-load initialization
       * work with Genesys Cloud.  Implementers should call bootstrapped() after initialization work is
       * complete.  Genesys Cloud will eventually timeout and show the app anyway if the bootstrapped()
       * function is not called in a timely manor.
       *
       * #### Required Lifecycle Hooks ([More Info](/api/client-apps/advanced.html#lifecycle_events))
       * * `bootstrap`
       *
       * ```ts
       * myClientApp.lifecycle.addBootstrapListener(() => {
       *   // Perform bootstrap (post-load init) work
       *
       *   // Simulate 500ms delay
       *   window.setTimeout(() => {
       *     myClientApp.lifecycle.bootstrapped();
       *   }, 500);
       * });
       * ```
       * 
       * @param listener - The function to call when Genesys Cloud is ready for the app to
       * perform post-load initialization work.  This function will be passed the lifecycle event and
       * does not augment the this context.
       * @param once - If the listener should only be invoked once or repeatedly; true by default.
       *
       * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events)
       *
       * @since 1.0.0
       */
      value: function addBootstrapListener(listener) {
        var once = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
        this.addMsgListener(LIFECYCLE_HOOK_EVENT_NAME, listener, {
          once: once,
          msgPayloadFilter: BOOTSTRAP_HOOK_FILTER
        });
      }
      /**
       * Signals Genesys Cloud that this app has finished its initialization work and
       * can be shown to the user.
       *
       * #### Required Lifecycle Hooks ([More Info](/api/client-apps/advanced.html#lifecycle_events))
       * * `bootstrap`
       *
       * ```ts
       * myClientApp.lifecycle.bootstrapped();
       * ```
       *
       * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events)
       *
       * @since 1.0.0
       */

    }, {
      key: "bootstrapped",
      value: function bootstrapped() {
        get(getPrototypeOf(LifecycleApi.prototype), "sendMsgToPc", this).call(this, 'bootstrapped');
      }
      /**
       * Remove a previously registered bootstrap lifecycle event listener.
       *
       * #### Required Lifecycle Hooks ([More Info](/api/client-apps/advanced.html#lifecycle_events))
       * * `bootstrap`
       * 
       * ```ts
       * let onBootstrap = evt => {
       *   // Perform bootstrap (post-load init) work
       *
       *   // Remove the listener. [Note:] once must be provided to match
       *   myClientApp.lifecycle.removeBootstrapListener(onBootstrap, false);
       * };
       * // Note once must be set to false or the listener will be auto-removed by default
       * myClientApp.lifecycle.addBootstrapListener(onBootstrap, false);
       * ```
       *
       * @param listener - The previously registered bootstrap event listener.
       * @param once - false if once was explicitly set as false when adding the listener;
       *  otherwise, you can explicitly provide true or rely on the default.
       *
       * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events)
       *
       * @since 1.0.0
       */

    }, {
      key: "removeBootstrapListener",
      value: function removeBootstrapListener(listener) {
        var once = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
        this.removeMsgListener(LIFECYCLE_HOOK_EVENT_NAME, listener, {
          once: once,
          msgPayloadFilter: BOOTSTRAP_HOOK_FILTER
        });
      }
      /**
       * Attach a listener function to be called when the user has re-focused your app.
       * [Note:] Focus is not called on initial show.  Use the bootstrap listener for that work.
       *
       * #### Required Lifecycle Hooks ([More Info](/api/client-apps/advanced.html#lifecycle_events))
       * * `focus`
       * 
       * ```ts
       * let onFocus = evt => {
       *   // Perform focus work
       * };
       * myClientApp.lifecycle.addFocusListener(onFocus);
       *
       * // Don't forget to remove this listener inside the stop event listener
       * myClientApp.lifecycle.addStopListener(() => {
       *   myClientApp.lifecycle.removeFocusListener(onFocus);
       * });
       * ```
       *
       * @param listener - The function to call when the user has re-focused your app in the UI.
       * @param once - If the listener should only be invoked once or repeatedly; false by default.
       *
       * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events)
       *
       * @since 1.0.0
       */

    }, {
      key: "addFocusListener",
      value: function addFocusListener(listener) {
        var once = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
        this.addMsgListener(LIFECYCLE_HOOK_EVENT_NAME, listener, {
          once: once,
          msgPayloadFilter: FOCUS_HOOK_FILTER
        });
      }
      /**
       * Remove a previously registered focus lifecycle event listener
       *
       * #### Required Lifecycle Hooks ([More Info](/api/client-apps/advanced.html#lifecycle_events))
       * * `focus`
       * 
       * ```ts
       * let onFocus = evt => {
       *   // Perform focus work
       * };
       * myClientApp.lifecycle.addFocusListener(onFocus);
       *
       * // Don't forget to remove this listener inside the stop event listener
       * myClientApp.lifecycle.addStopListener(() => {
       *   myClientApp.lifecycle.removeFocusListener(onFocus);
       * });
       * ```
       *
       * @param listener - The previously registered focus event listener.
       * @param once - true if once was explicitly set as true when adding the listener;
       *  otherwise, you can explicitly provide false or rely on the default.
       *
       * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events)
       *
       * @since 1.0.0
       */

    }, {
      key: "removeFocusListener",
      value: function removeFocusListener(listener) {
        var once = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
        this.removeMsgListener(LIFECYCLE_HOOK_EVENT_NAME, listener, {
          once: once,
          msgPayloadFilter: FOCUS_HOOK_FILTER
        });
      }
      /**
       * Attach a listener function to be called when the user has left/blurred your app.
       *
       * #### Required Lifecycle Hooks ([More Info](/api/client-apps/advanced.html#lifecycle_events))
       * * `blur`
       * 
       * ```ts
       * let onBlur = evt => {
       *   // Perform blur work
       * };
       * myClientApp.lifecycle.addBlurListener(onBlur);
       *
       * // Don't forget to remove this listener inside the stop event listener
       * myClientApp.lifecycle.addStopListener(() => {
       *   myClientApp.lifecycle.removeBlurListener(onBlur);
       * });
       * ```
       *
       * @param listener - The function to call when the user has left your
       * app in the UI.
       * @param once - If the listener should only be invoked once or repeatedly; false by default.
       *
       * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events)
       *
       * @since 1.0.0
       */

    }, {
      key: "addBlurListener",
      value: function addBlurListener(listener) {
        var once = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
        this.addMsgListener(LIFECYCLE_HOOK_EVENT_NAME, listener, {
          once: once,
          msgPayloadFilter: BLUR_HOOK_FILTER
        });
      }
      /**
       * Remove a previously registered blur lifecycle event listener
       *
       * #### Required Lifecycle Hooks ([More Info](/api/client-apps/advanced.html#lifecycle_events))
       * * `blur`
       * 
       * ```ts
       * let onBlur = evt => {
       *   // Perform blur work
       * };
       * myClientApp.lifecycle.addBlurListener(onBlur);
       *
       * // Don't forget to remove this listener inside the stop event listener
       * myClientApp.lifecycle.addStopListener(() => {
       *   myClientApp.lifecycle.removeBlurListener(onBlur);
       * });
       * ```
       *
       * @param listener - The previously registered blur event listener.
       * @param once - true if once was explicitly set as true when adding the listener;
       *  otherwise, you can explicitly provide false or rely on the default.
       *
       * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events)
       *
       * @since 1.0.0
       */

    }, {
      key: "removeBlurListener",
      value: function removeBlurListener(listener) {
        var once = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
        this.removeMsgListener(LIFECYCLE_HOOK_EVENT_NAME, listener, {
          once: once,
          msgPayloadFilter: BLUR_HOOK_FILTER
        });
      }
      /**
       * Attach a listener function to be called when Genesys Cloud is about to shut down your app.
       * For instance, this can happen if the user has loaded too many apps and your app needs to be
       * stopped to conserve resources.
       *
       * This provides a hook for you to do any app cleanup work.  Implementers should call
       * stopped() after shutdown work is complete.  Genesys Cloud will eventually timeout and permanenty
       * remove the app anyway if stopped() is not called in a timely manor.
       *
       * #### Required Lifecycle Hooks ([More Info](/api/client-apps/advanced.html#lifecycle_events))
       * * `stop`
       * 
       * ```ts
       * myClientApp.lifecycle.addStopListener(() => {
       *   // Perform shutdown work
       *
       *   // Simulate 500ms delay
       *   window.setTimeout(() => {
       *     myClientApp.lifecycle.stopped();
       *   }, 500);
       * });
       * ```
       *
       * @param listener - The function to call when Genesys Cloud is about to stop this app.
       * This function will be passed the lifecycle event and does not augment the this context.
       * @param once - If the listener should only be invoked once or repeatedly; true by default.
       *
       * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events)
       *
       * @since 1.0.0
       */

    }, {
      key: "addStopListener",
      value: function addStopListener(listener) {
        var once = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
        this.addMsgListener(LIFECYCLE_HOOK_EVENT_NAME, listener, {
          once: once,
          msgPayloadFilter: STOP_HOOK_FILTER
        });
      }
      /**
       * Signals Genesys Cloud that this app has finished its tear down work and the iframe
       * can be removed from Genesys Cloud permanently.
       *
       * #### Required Lifecycle Hooks ([More Info](/api/client-apps/advanced.html#lifecycle_events))
       * * `stop`
       *
       * ```ts
       * myClientApp.lifecycle.stopped();
       * ```
       *
       * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events)
       *
       * @since 1.0.0
       */

    }, {
      key: "stopped",
      value: function stopped() {
        get(getPrototypeOf(LifecycleApi.prototype), "sendMsgToPc", this).call(this, 'stopped');
      }
      /**
       * Remove a previously registered stop lifecycle event listener.
       *
       * #### Required Lifecycle Hooks ([More Info](/api/client-apps/advanced.html#lifecycle_events))
       * * `stop`
       * 
       * ```ts
       * let onStop = evt => {
       *   // Perform cleanup work
       *
       *   // Don't forget to notify Genesys Cloud on complete
       *   myClientApp.lifecycle.stopped();
       *
       *   // Remove the stop listener (since you passed false for the once option)
       *   // Note: You must also pass false for once to match the listener
       *   myClientApp.lifecycle.removeStopListener(onStop, false);
       * };
       * // Note: once must be set to false or the listener will be auto-removed by default
       * myClientApp.lifecycle.addStopListener(onStop, false);
       * ```
       *
       * @param listener - The previously registered stop event listener.
       * @param once - false if once was explicitly set as false when adding the listener;
       *  otherwise, you can explicitly provide true or rely on the default.
       *
       * @see [Advanced Application Concepts - Lifecycle Events](/api/client-apps/advanced.html#lifecycle_events)
       *
       * @since 1.0.0
       */

    }, {
      key: "removeStopListener",
      value: function removeStopListener(listener) {
        var once = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
        this.removeMsgListener(LIFECYCLE_HOOK_EVENT_NAME, listener, {
          once: once,
          msgPayloadFilter: STOP_HOOK_FILTER
        });
      }
    }]);

    return LifecycleApi;
  }(BaseApi);

  function _createSuper$2(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct$2(); return function _createSuperInternal() { var Super = getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return possibleConstructorReturn(this, result); }; }

  function _isNativeReflectConstruct$2() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }
  /**
   * Utilities for interacting with general Genesys Cloud App UI components
   *
   * @noInheritDoc
   * @since 1.0.0
   */

  var CoreUiApi = /*#__PURE__*/function (_BaseApi) {
    inherits(CoreUiApi, _BaseApi);

    var _super = _createSuper$2(CoreUiApi);

    function CoreUiApi() {
      classCallCheck(this, CoreUiApi);

      return _super.apply(this, arguments);
    }

    createClass(CoreUiApi, [{
      key: "showHelp",

      /**
       * Show the help UI.  Noop if already shown.
       *
       * ```ts
       * myClientApp.coreUi.showHelp();
       * ```
       *
       * @since 1.0.0
       */
      value: function showHelp() {
        get(getPrototypeOf(CoreUiApi.prototype), "sendMsgToPc", this).call(this, 'showHelp');
      }
      /**
       * Open the help panel to the specified Resource Center artifact
       *
       * ```ts
       * // Direct path
       * myClientApp.coreUi.showResourceCenterArtifact('articles/complete-profile');
       * ```
       *
       * ```ts
       * // Permalink
       * myClientApp.coreUi.showResourceCenterArtifact('?p=7711');
       * ```
       * 
       * @param artifactRelPath - The path of the Resource Center artifact
       * relative to the Resource Center root.  Supports paths and query string params,
       * but not hash params.  The appropriate theme will be inserted automatically.
       *
       * @since 1.0.0
       */

    }, {
      key: "showResourceCenterArtifact",
      value: function showResourceCenterArtifact(artifactRelPath) {
        get(getPrototypeOf(CoreUiApi.prototype), "sendMsgToPc", this).call(this, 'showResourceCenterArtifact', {
          resourceCenterRelPath: artifactRelPath
        });
      }
      /**
       * Hide the help UI.  Noop if already hidden.
       *
       * ```ts
       * myClientApp.coreUi.hideHelp();
       * ```
       *
       * @since 1.0.0
       */

    }, {
      key: "hideHelp",
      value: function hideHelp() {
        get(getPrototypeOf(CoreUiApi.prototype), "sendMsgToPc", this).call(this, 'hideHelp');
      }
      /**
       * Open a URL in a new window.
       *
       * ```ts
       * myClientApp.coreUi.openWindow("https://en.wikipedia.org/wiki/Main_Page");
       * ```
       *
       * @param targetUrl - The URL to open in a new window
       *
       * @since 2.3.0
       */

    }, {
      key: "openWindow",
      value: function openWindow(targetUrl) {
        get(getPrototypeOf(CoreUiApi.prototype), "sendMsgToPc", this).call(this, 'openWindow', {
          targetUrl: targetUrl
        });
      }
    }]);

    return CoreUiApi;
  }(BaseApi);

  function _createSuper$3(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct$3(); return function _createSuperInternal() { var Super = getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return possibleConstructorReturn(this, result); }; }

  function _isNativeReflectConstruct$3() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }
  /**
   * Utilities for interacting with users in the Genesys Cloud Client
   *
   * @noInheritDoc
   * @since 1.0.0
   *
   * @deprecated Use {@link DirectoryApi} instead. (Since 2.3.0)
   */

  var UsersApi = /*#__PURE__*/function (_BaseApi) {
    inherits(UsersApi, _BaseApi);

    var _super = _createSuper$3(UsersApi);

    function UsersApi() {
      classCallCheck(this, UsersApi);

      return _super.apply(this, arguments);
    }

    createClass(UsersApi, [{
      key: "showProfile",

      /**
       * Shows the profile of a specified user
       *
       * ```ts
       * myClientApp.users.showProfile("targetUserId");
       * ```
       *
       * @param userId - The id of the user to show
       *
       * @since 1.0.0
       *
       * @deprecated Use {@link ClientApp#directory#showUser} instead. (Since 2.3.0)
       *
       * @see [DirectoryApi#showUser](directoryapi.md#showuser) for a replacement.
       */
      value: function showProfile(userId) {
        get(getPrototypeOf(UsersApi.prototype), "sendMsgToPc", this).call(this, 'showProfile', {
          'profileId': userId
        });
      }
    }]);

    return UsersApi;
  }(BaseApi);

  function _createSuper$4(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct$4(); return function _createSuperInternal() { var Super = getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return possibleConstructorReturn(this, result); }; }

  function _isNativeReflectConstruct$4() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }
  /**
   * Utilities for interacting with the company directory in the Genesys Cloud Client
   *
   * @noInheritDoc
   * @since 2.3.0
   */

  var DirectoryApi = /*#__PURE__*/function (_BaseApi) {
    inherits(DirectoryApi, _BaseApi);

    var _super = _createSuper$4(DirectoryApi);

    function DirectoryApi() {
      classCallCheck(this, DirectoryApi);

      return _super.apply(this, arguments);
    }

    createClass(DirectoryApi, [{
      key: "showUser",

      /**
       * Shows the profile of a specified user
       *
       * ```ts
       * myClientApp.directory.showUser("targetUserId");
       * ```
       *
       * @param userId - The id of the user to show
       *
       * @since 2.3.0
       */
      value: function showUser(userId) {
        get(getPrototypeOf(DirectoryApi.prototype), "sendMsgToPc", this).call(this, 'showProfile', {
          profileId: userId
        });
      }
      /**
       * Shows the specified group
       *
       * ```ts
       * myClientApp.directory.showGroup("targetGroupId");
       * ```
       *
       * @param groupId - The id of the group to show
       *
       * @since 2.3.0
       */

    }, {
      key: "showGroup",
      value: function showGroup(groupId) {
        get(getPrototypeOf(DirectoryApi.prototype), "sendMsgToPc", this).call(this, 'showGroup', {
          groupId: groupId
        });
      }
    }]);

    return DirectoryApi;
  }(BaseApi);

  function _createSuper$5(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct$5(); return function _createSuperInternal() { var Super = getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return possibleConstructorReturn(this, result); }; }

  function _isNativeReflectConstruct$5() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }
  /**
   * Utilities for interacting with Genesys Cloud conversations
   *
   * @noInheritDoc
   * @since 1.1.0
   */

  var ConversationsApi = /*#__PURE__*/function (_BaseApi) {
    inherits(ConversationsApi, _BaseApi);

    var _super = _createSuper$5(ConversationsApi);

    function ConversationsApi() {
      classCallCheck(this, ConversationsApi);

      return _super.apply(this, arguments);
    }

    createClass(ConversationsApi, [{
      key: "showInteractionDetails",

      /**
       * Show an interaction by ID.
       *
       * Required Permissions:
       * * ALL Of
       *     * analytics:conversationDetail:view
       *     * analytics:conversationAggregate:view
       *     * ANY Of
       *         * conversation:communication:view
       *         * quality:evaluation:add
       *         * quality:calibration:view
       *         * quality:evaluation:editScore
       *
       * ```ts
       * myClientApp.conversations.showInteractionDetails('af2ef59d-9bc5-4436-8738-97c04869c81c');
       * ```
       *
       * @since 1.1.0
       */
      value: function showInteractionDetails(conversationId) {
        get(getPrototypeOf(ConversationsApi.prototype), "sendMsgToPc", this).call(this, 'showInteractionDetails', {
          conversationId: conversationId
        });
      }
      /**
       * Send a message to be filled into the interaction message box for the agent to review and send.
       * This function works specifically with a bound interaction when both the interaction and calling app
       * are visible, it is not intended (and will not work) for situations where the interaction is not active.
       * Furthermore, this function should only be called in response to user interaction to ensure the agent is
       * aware of the impending text insertion and so their existing draft state is not unexpectedly altered.
       * 
       * @param mode - The insertion mode to use when injecting the text into the agent's text box.
       * 'insert' -> injects text at agent's cursor position, leaving other text intact.
       * 
       * @param message - The message to inject into the agent's text box.
       */

    }, {
      key: "proposeInteractionMessage",
      value: function proposeInteractionMessage(mode, message) {
        get(getPrototypeOf(ConversationsApi.prototype), "sendMsgToPc", this).call(this, 'proposeInteractionMessage', {
          mode: mode,
          message: message
        });
      }
    }]);

    return ConversationsApi;
  }(BaseApi);

  function _createSuper$6(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct$6(); return function _createSuperInternal() { var Super = getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return possibleConstructorReturn(this, result); }; }

  function _isNativeReflectConstruct$6() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }
  /**
   * Utilities for showing agent level interaction and evaluation details
   *
   * @noInheritDoc
   * @since 1.3.0
   */

  var MyConversationsApi = /*#__PURE__*/function (_BaseApi) {
    inherits(MyConversationsApi, _BaseApi);

    var _super = _createSuper$6(MyConversationsApi);

    function MyConversationsApi() {
      classCallCheck(this, MyConversationsApi);

      return _super.apply(this, arguments);
    }

    createClass(MyConversationsApi, [{
      key: "showInteractionDetails",

      /**
       * Show an agent his/her interaction by ID.
       *
       * Required Permissions:
       * * ALL Of
       *     * User must be an Agent participant on the conversation
       *     * ONE Of
       *         * Implicit Conversation Access via participant on the Conversation
       *         * conversation:communication:view
       *
       * ```ts
       * myClientApp.myConversations.showInteractionDetails(
       *   'B1B0B92B-B944-4F5D-AF62-8E5BAFFC9298',
       * );
       * ```
       * 
       * @param conversationId The id of the conversation
       * 
       * @since 1.3.0
       */
      value: function showInteractionDetails(conversationId) {
        get(getPrototypeOf(MyConversationsApi.prototype), "sendMsgToPc", this).call(this, 'showMyInteractionDetails', {
          'conversationId': conversationId
        });
      }
      /**
       * Show an agent his/her evaluation details by conversation and evaluation IDs.
       *
       * Required Permissions:
       * * ALL Of
       *     * User must be the Agent evaluated on the specified conversation/evaluation
       *     * quality:evaluation:view
       * 
       * ```ts
       * myClientApp.myConversations.showEvaluationDetails(
       *   'B1B0B92B-B944-4F5D-AF62-8E5BAFFC9298',
       *   '0E3759CE-2275-4480-BB15-3D4717446F93',
       * );
       * ```
       *
       * @param conversationId The id of the conversation
       * @param evaluationId The id of the evaluation
       *
       * @since 1.3.0
       */

    }, {
      key: "showEvaluationDetails",
      value: function showEvaluationDetails(conversationId, evaluationId) {
        get(getPrototypeOf(MyConversationsApi.prototype), "sendMsgToPc", this).call(this, 'showMyEvaluationDetails', {
          'conversationId': conversationId,
          'evaluationId': evaluationId
        });
      }
    }]);

    return MyConversationsApi;
  }(BaseApi);

  function _createSuper$7(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct$7(); return function _createSuperInternal() { var Super = getPrototypeOf(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = getPrototypeOf(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return possibleConstructorReturn(this, result); }; }

  function _isNativeReflectConstruct$7() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }
  /**
   * Utilities for interacting with External Contacts
   *
   * @noInheritDoc
   * @since 1.4.0
   */

  var ExternalContactsApi = /*#__PURE__*/function (_BaseApi) {
    inherits(ExternalContactsApi, _BaseApi);

    var _super = _createSuper$7(ExternalContactsApi);

    function ExternalContactsApi() {
      classCallCheck(this, ExternalContactsApi);

      return _super.apply(this, arguments);
    }

    createClass(ExternalContactsApi, [{
      key: "showExternalContactProfile",

      /**
       * Show an external contact by ID.
       *
       * Required Permissions:
       * * ANY Of
       *     * externalContacts:contact:view
       *
       * ```ts
       * myClientApp.externalContacts.showExternalContactProfile('b33491ce-0a84-4959-9273-848901d6db11');
       * ```
       *
       * @since 1.4.0
       */
      value: function showExternalContactProfile(externalContactId) {
        get(getPrototypeOf(ExternalContactsApi.prototype), "sendMsgToPc", this).call(this, 'showExternalContactProfile', {
          contactId: externalContactId
        });
      }
      /**
       * Show an external organization by ID.
       *
       * Required Permissions:
       * * ANY Of
       *     * externalContacts:externalOrganization:view
       *
       * ```ts
       * myClientApp.externalContacts.showExternalOrganizationProfile('8a0db7c8-c4a3-4577-b41e-aa40a6408f1c');
       * ```
       *
       * @since 1.4.0
       */

    }, {
      key: "showExternalOrganizationProfile",
      value: function showExternalOrganizationProfile(externalOrganizationId) {
        get(getPrototypeOf(ExternalContactsApi.prototype), "sendMsgToPc", this).call(this, 'showExternalOrganizationProfile', {
          externalOrganizationId: externalOrganizationId
        });
      }
    }]);

    return ExternalContactsApi;
  }(BaseApi);

  /**
   * Provides bi-directional communication and integration between this instance of a Genesys Cloud Client Application
   * and the Genesys Cloud host application
   */

  var ClientApp = /*#__PURE__*/function () {
    /**
     * The private reference to the known PC environment which is set, inferred, or defaulted by the config provided to the instance.
     */

    /**
     * The private reference to the custom origin, if provided.
     */

    /**
     * The AlertingApi instance.
     *
     * ```ts
     * let clientApp = new ClientApp({
     *   gcHostOriginQueryParam: 'gcHostOrigin',
     *   gcTargetEnvQueryParam: 'gcTargetEnv'
     * });
     *
     * clientApp.alerting.someMethod(...);
     * ```
     */

    /**
     * The LifecycleApi instance.
     *
     * ```ts
     * let clientApp = new ClientApp({
     *   gcHostOriginQueryParam: 'gcHostOrigin',
     *   gcTargetEnvQueryParam: 'gcTargetEnv'
     * });
     *
     * clientApp.lifecycle.someMethod(...);
     * ```
     */

    /**
     * The CoreUIApi instance.
     *
     * ```ts
     * let clientApp = new ClientApp({
     *   gcHostOriginQueryParam: 'gcHostOrigin',
     *   gcTargetEnvQueryParam: 'gcTargetEnv'
     * });
     *
     * clientApp.coreUi.someMethod(...);
     * ```
     */

    /**
     * The UsersApi instance.
     *
     * ```ts
     * let clientApp = new ClientApp({
     *   gcHostOriginQueryParam: 'gcHostOrigin',
     *   gcTargetEnvQueryParam: 'gcTargetEnv'
     * });
     *
     * clientApp.users.someMethod(...);
     * ```
     *
     * @deprecated Use {@link directory} property instead. (Since 2.3.0)
     */

    /**
     * The DirectoryApi instance.
     *
     * ```ts
     * let clientApp = new ClientApp({
     *   gcHostOriginQueryParam: 'gcHostOrigin',
     *   gcTargetEnvQueryParam: 'gcTargetEnv'
     * });
     *
     * clientApp.directory.someMethod(...);
     * ```
     * @since 2.3.0
     */

    /**
     * The ConversationsApi instance.
     *
     * ```ts
     * let clientApp = new ClientApp({
     *   gcHostOriginQueryParam: 'gcHostOrigin',
     *   gcTargetEnvQueryParam: 'gcTargetEnv'
     * });
     *
     * clientApp.conversations.someMethod(...);
     * ```
     */

    /**
     * The MyConversationsApi instance.
     *
     * ```ts
     * let clientApp = new ClientApp({
     *   gcHostOriginQueryParam: 'gcHostOrigin',
     *   gcTargetEnvQueryParam: 'gcTargetEnv'
     * });
     *
     * clientApp.myConversations.someMethod(...);
     * ```
     *
     * @since 1.3.0
     */

    /**
     * The External Contacts instance.
     *
     * ```ts
     * let clientApp = new ClientApp({
     *   gcHostOriginQueryParam: 'gcHostOrigin',
     *   gcTargetEnvQueryParam: 'gcTargetEnv'
     * });
     *
     * clientApp.externalContacts.someMethod(...);
     * ```
     *
     * @since 1.4.0
     */

    /**
     * Constructs an instance of a Genesys Cloud Client Application to communicate with Genesys Cloud
     *
     * ```ts
     * let clientApp = new ClientApp({
     *   gcHostOriginQueryParam: 'gcHostOrigin',
     *   gcTargetEnvQueryParam: 'gcTargetEnv'
     * });
     * ```
     *
     * @param cfg - Runtime config of the client
     */
    function ClientApp() {
      var cfg = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

      classCallCheck(this, ClientApp);

      defineProperty(this, "_pcEnv", null);

      defineProperty(this, "_customPcOrigin", null);

      defineProperty(this, "alerting", void 0);

      defineProperty(this, "lifecycle", void 0);

      defineProperty(this, "coreUi", void 0);

      defineProperty(this, "users", void 0);

      defineProperty(this, "directory", void 0);

      defineProperty(this, "conversations", void 0);

      defineProperty(this, "myConversations", void 0);

      defineProperty(this, "externalContacts", void 0);

      if (cfg) {
        var parsedQueryString = queryString.parse(ClientApp._getQueryString() || '');

        if ('gcHostOriginQueryParam' in cfg || 'gcTargetEnvQueryParam' in cfg) {
          this.assertNonEmptyString(cfg.gcHostOriginQueryParam, 'host origin query param name');
          this.assertNonEmptyString(cfg.gcTargetEnvQueryParam, 'target env query param name');
          var parsedGcHostOrigin = parsedQueryString[cfg.gcHostOriginQueryParam];
          var parsedGcTargetEnv = parsedQueryString[cfg.gcTargetEnvQueryParam];
          this.assertNonEmptyString(parsedGcHostOrigin, 'host origin parsed query param');
          this.assertNonEmptyString(parsedGcTargetEnv, 'target env parsed query param');
          this._pcEnv = this.lookupGcEnv(parsedGcHostOrigin, parsedGcTargetEnv);
        } else if ('gcHostOrigin' in cfg || 'gcTargetEnv' in cfg) {
          this.assertNonEmptyString(cfg.gcHostOrigin, 'gcHostOrigin');
          this.assertNonEmptyString(cfg.gcTargetEnv, 'gcTargetEnv');
          this._pcEnv = this.lookupGcEnv(cfg.gcHostOrigin, cfg.gcTargetEnv);
        } else if ('pcEnvironmentQueryParam' in cfg) {
          var paramName = cfg.pcEnvironmentQueryParam;
          this.assertNonEmptyString(paramName, 'query param name');
          var paramValue = parsedQueryString[paramName];
          this.assertNonEmptyString(paramValue, "value for query param '".concat(paramName, "'"));
          this._pcEnv = this.lookupEnv(paramValue);
        } else if ('pcEnvironment' in cfg) {
          this.assertNonEmptyString(cfg.pcEnvironment, 'pcEnvironment');
          this._pcEnv = this.lookupEnv(cfg.pcEnvironment);
        } else if ('pcOrigin' in cfg) {
          this.assertNonEmptyString(cfg.pcOrigin, 'pcOrigin');
          this._customPcOrigin = cfg.pcOrigin;
        }
      }

      if (!this._pcEnv && !this._customPcOrigin) {
        // Use the default PC environment
        this._pcEnv = DEFAULT_PC_ENV;
      }

      var apiCfg = {
        targetPcOrigin: this._pcEnv ? this._pcEnv.pcAppOrigin : this._customPcOrigin
      };
      this.alerting = new AlertingApi(apiCfg);
      this.lifecycle = new LifecycleApi(apiCfg);
      this.coreUi = new CoreUiApi(apiCfg);
      this.users = new UsersApi(apiCfg);
      this.directory = new DirectoryApi(apiCfg);
      this.conversations = new ConversationsApi(apiCfg);
      this.myConversations = new MyConversationsApi(apiCfg);
      this.externalContacts = new ExternalContactsApi(apiCfg);
    }

    createClass(ClientApp, [{
      key: "assertNonEmptyString",
      value: function assertNonEmptyString(value, name) {
        if (typeof value !== 'string' || value.trim().length === 0) {
          throw new Error("Invalid ".concat(name, " provided.  Must be a non-null, non-empty string"));
        }
      }
    }, {
      key: "lookupEnv",
      value: function lookupEnv(env, envTlds, hostAppDevOrigin) {
        var pcEnv = lookupPcEnv(env, true, envTlds, hostAppDevOrigin);
        if (!pcEnv) throw new Error("Could not parse '".concat(env, "' into a known PureCloud environment"));
        return pcEnv;
      }
    }, {
      key: "lookupGcEnv",
      value: function lookupGcEnv$1(hostOrigin, targetEnv, envs) {
        var pcEnv = lookupGcEnv(hostOrigin, targetEnv, envs);

        if (!pcEnv) throw new Error("Could not parse ".concat(hostOrigin, " (").concat(targetEnv, ") into a known GenesysCloud environment"));
        return pcEnv;
      }
      /**
       * Returns the pcEnvironment (e.g. mypurecloud.com, mypurecloud.jp) if known; null otherwise.
       * This value will be available if a valid Genesys Cloud Environment is provided, inferred, or
       * defaulted from the config passed to this instance.
       *
       * @returns the valid Genesys Cloud environment; null if unknown.
       *
       * @since 1.0.0
       */

    }, {
      key: "pcEnvironment",
      get: function get() {
        return this.gcEnvironment;
      }
      /**
       * Returns the gcEnvironment (e.g. mypurecloud.com, mypurecloud.jp) if known; null otherwise.
       * This value will be available if a valid Genesys Cloud Environment is provided, inferred, or
       * defaulted from the config passed to this instance.
       *
       * @returns the valid Genesys Cloud environment; null if unknown.
       *
       * @since 2.6.3
       */

    }, {
      key: "gcEnvironment",
      get: function get() {
        return this._pcEnv ? this._pcEnv.pcEnvTld : null;
      }
      /**
       * Displays the version of the PureClound Client App SDK.
       *
       * ```ts
       * ClientApp.version
       * ```
       *
       * @returns The version of the Genesys Cloud Client App SDK
       *
       * @since 1.0.0
       */

    }], [{
      key: "about",

      /**
       * Displays information about this version of the PureClound Client App SDK.
       *
       * ```ts
       * ClientApp.about(); // SDK details returned as a string
       * ```
       *
       * @returns A string of information describing this library
       *
       * @since 1.0.0
       */
      value: function about() {
        return "purecloud-client-app-sdk".concat("v", "2.6.6");
      }
      /**
       * A private utility method
       *
       * @ignore
       */

    }, {
      key: "_getQueryString",
      value: function _getQueryString() {
        return window && window.location ? window.location.search : null;
      }
    }, {
      key: "version",
      get: function get() {
        return "2.6.6";
      }
    }]);

    return ClientApp;
  }();

  return ClientApp;

})));
