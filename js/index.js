var config = {
  projectId: "crypto-hash-benchmarks",
  apiKey: "AIzaSyASUJqyimyzk7YfCY2yPUFQ3z2wh9yxI_c",
  databaseURL: "https://crypto-hash-benchmarks.firebaseio.com"
};
firebase.initializeApp(config);
var database = firebase.database;
//------------------------------------------------------------------------------------
asmCrypto.random.skipSystemRNGWarning = true;
function bytesToHex(arrayBuffer) {
  var bytes = new Uint8Array(arrayBuffer);
  var hex = "";
  for (n in bytes) {
    hex += ("0" + (0xff & bytes[n]).toString(16)).slice(-2);
  }
  return hex;
}
var passLength = 24;
var keyLength = 24;

var crypto = window.msCrypto || window.crypto;
var salt = crypto.getRandomValues(new Uint8Array(passLength));
var stringSalt = String.fromCharCode.apply(null, salt);
var iterations = 1000;
var rawPass = crypto.getRandomValues(new Uint8Array(passLength));
var stringPass = String.fromCharCode.apply(null, rawPass);
var id = bytesToHex(rawPass).substr(0,4);
var nativeKey;
var results = {platform: platform, benchmarks: {}, "string-pass": bytesToHex(rawPass), salt: bytesToHex(salt), version: "1.0"};

//----------------------------------------------------------------------------------
function generateNativeKey(deferred) {
  try {
    var p = crypto.subtle.importKey(
      "raw",
      rawPass,
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );
    if (!p.then) {
      p.oncomplete = function(event) {
        nativeKey = event.target.result;
        deferred.resolve();
      };
    } else {
      p
        .then(function(pass) {
          nativeKey = pass;
          if (deferred) {
            deferred.resolve();
          }
        })
        .catch(function(err) {
          console.error(err);
          if (deferred) {
            deferred.resolve();
          }
        });
    }
  } catch (e) {
    //e.message == "NotSupportedError"
    console.log(e);
    deferred.resolve();
  }
}

function nativePBKDF2(deferred) {
  try {
    var p = crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: iterations,
        hash: { name: "SHA-1" }
      },
      nativeKey,
      keyLength * 8
    );
    if (!p.then) {
      p.oncomplete = function(event) {
        if (!deferred) {
          console.log(bytesToHex(event.target.result));
        } else {
          deferred.resolve();
        }
      };
    } else {
      p
        .then(function(bits) {
          if (!deferred) {
            console.log(bytesToHex(bits));
          } else {
            deferred.resolve();
          }
        })
        .catch(function(err) {
          console.error(err);
          if (deferred) {
            deferred.benchmark.abort();
          }
        });
    }
  } catch (e) {
    console.log(e);
    deferred.benchmark.abort();
  }
}

function nativeSHA(type, deferred) {
  try {
    var p = crypto.subtle.digest(
      {
        name: type
      },
      rawPass
    );
    if (!p.then) {
      p.oncomplete = function(event) {
        if (!deferred) {
          console.log(bytesToHex(event.target.result));
        } else {
          deferred.resolve();
        }
      };
    } else {
      p
        .then(function(hash) {
          if (!deferred) {
            console.log(bytesToHex(hash));
          } else {
            deferred.resolve();
          }
        })
        .catch(function(err) {
          console.error(err);
          if (deferred) {
            deferred.benchmark.abort();
          }
        });
    }
  } catch (e) {
    console.log(e);
    deferred.benchmark.abort();
  }
}

function onComplete(event) {
  var res = event.target;
  if (!res.aborted) {
    console.log("" + res);
    var name = res.name;
    var execPerSec = res.hz.toFixed(res.hz < 100 ? 2 : 0);
    var error = res.stats.rme.toFixed(2);
    var sample = res.stats.sample.length;
    var index = name.indexOf('-');
    var lib = name.substring(0, index);
    var alg = name.substring(index+1);
    results.benchmarks[lib] = results.benchmarks[lib] || {};
    results.benchmarks[lib][alg] = {
      execPerSec: execPerSec,
      error: error,
      sample: sample
    };

    var element = document.querySelector("#" + name);
    if (element) {
      element.classList.remove("in-progress");
      element.classList.add("completed");
      element.innerHTML = execPerSec + " ops/sec \u00B1" + error + "%";
    }
  }
}
function onAbort(event) {
  var res = event.target;
  console.log("Aborted: " + res);
  var name = res.name;
  var index = name.indexOf('-');
  var lib = name.substring(0, index);
  var alg = name.substring(index+1);
  results.benchmarks[lib] = results.benchmarks[lib] || {};
  results.benchmarks[lib][alg] = {aborted:true};
  results.benchmarks[lib][alg].msg = res.error && res.error.message;
  var element = document.querySelector("#" + name);
  if (element) {
    element.classList.remove("in-progress");
    element.classList.add("failed");
    element.innerHTML = "failed";
  }
}

function onStart(benchmark) {
  var element = document.querySelector("#" + benchmark.name);
  if (element) {
    element.classList.add("in-progress");
  }
}

function createBenchmark(name, fn, defer) {
  var options = {
    defer: !!defer,
    fn: fn,
    onComplete: onComplete,
    onAbort: onAbort
  };
  return new Benchmark(name, options);
}

var nativeSHA1 = createBenchmark(
  "native-sha1",
  function(deferred) {
    nativeSHA("SHA-1", deferred);
  },
  true
);
var nativeSHA256 = createBenchmark(
  "native-sha256",
  function(deferred) {
    nativeSHA("SHA-256", deferred);
  },
  true
);
var nativeSHA512 = createBenchmark(
  "native-sha512",
  function(deferred) {
    nativeSHA("SHA-512", deferred);
  },
  true
);
var nativePBKDF2 = createBenchmark("native-pbkdf2", nativePBKDF2, true);

function waitAfter(func, millisec) {
  return new Promise(function(resolve, reject) {
    func();
    setTimeout(resolve, millisec);
  });
}

function asyncRun() {
  var benchmark = this;
  return waitAfter(onStart.bind(null, benchmark), 50).then(function() {
    return new Promise(function(resolve, reject) {
      benchmark.on("complete abort", resolve).run();
    });
  });
}

function runNativeBenchmarks() {
  return asyncRun
    .call(nativeSHA1)
    .then(asyncRun.bind(nativeSHA256))
    .then(asyncRun.bind(nativeSHA512))
    .then(function() {
      return new Promise(function(resolve, reject) {
        generateNativeKey({ resolve: resolve, reject: reject });
      });
    })
    .then(asyncRun.bind(nativePBKDF2));
}

//-------------------------------------------------------------------------------------

function forge_hash(type) {
  return function() {
    var md = forge.md[type].create();
    md.update(rawPass);
    return md.digest();
  };
}

function forge_pbkdf2() {
  return forge.pkcs5.pbkdf2(stringPass, salt, iterations, 24);
}

var forgeMD5 = createBenchmark("forge-md5", forge_hash("md5"));
var forgeSHA1 = createBenchmark("forge-sha1", forge_hash("sha1"));
var forgeSHA256 = createBenchmark("forge-sha256", forge_hash("sha256"));
var forgeSHA512 = createBenchmark("forge-sha512", forge_hash("sha512"));
var forgePBKDF2 = createBenchmark("forge-pbkdf2", forge_pbkdf2);

function runForgeBenchmarks() {
  return asyncRun
    .call(forgeMD5)
    .then(asyncRun.bind(forgeSHA1))
    .then(asyncRun.bind(forgeSHA256))
    .then(asyncRun.bind(forgeSHA512))
    .then(asyncRun.bind(forgePBKDF2));
}

//---------------------------------------------------------------------------------------

var brwsrfy_md5 = md5.js;
var brwsrfy_sha1 = sha.js("sha1");
var brwsrfy_sha256 = sha.js("sha256");
var brwsrfy_sha512 = sha.js("sha512");

function browserify_md5() {
  return new brwsrfy_md5().update(stringPass).digest();
}
function browserify_sha1() {
  return brwsrfy_sha1.update(rawPass).digest();
}
function browserify_sha256() {
  return brwsrfy_sha256.update(rawPass).digest();
}
function browserify_sha512() {
  return brwsrfy_sha512.update(rawPass).digest();
}
function browserify_pbkdf2Async(deferred) {
  pbkdf2.pbkdf2(rawPass, salt, iterations, keyLength, "sha1", function(
    err,
    key
  ) {
    if (err) {
      if (deferred) {
        deferred.benchmark.abort();
      } else {
        throw err;
      }
    } else {
      if (deferred) {
        deferred.resolve();
      } else {
        console.log(key.toString("hex"));
      }
    }
  });
}

function browserify_pbkdf2() {
  return pbkdf2.pbkdf2Sync(rawPass, salt, keyLength, 24, "sha1");
}

var browserifyMD5 = createBenchmark("browserify-md5", browserify_md5);
var browserifySHA1 = createBenchmark("browserify-sha1", browserify_sha1);
var browserifySHA256 = createBenchmark("browserify-sha256", browserify_sha256);
var browserifySHA512 = createBenchmark("browserify-sha512", browserify_sha512);
var browserifyPBKDF2 = createBenchmark("browserify-pbkdf2", browserify_pbkdf2);
var browserifyPBKDF2Async = createBenchmark(
  "browserify-async-pbkdf2",
  browserify_pbkdf2Async,
  true
);

function runBrowserifyBenchmarks() {
  return asyncRun
    .call(browserifyMD5)
    .then(asyncRun.bind(browserifySHA1))
    .then(asyncRun.bind(browserifySHA256))
    .then(asyncRun.bind(browserifySHA512))
    .then(asyncRun.bind(browserifyPBKDF2))
    .then(asyncRun.bind(browserifyPBKDF2Async));
}

//------------------------------------------------------------------

function asmCrypto_sha1() {
  return asmCrypto.SHA1.bytes(rawPass);
}
function asmCrypto_sha256() {
  return asmCrypto.SHA256.bytes(rawPass);
}
function asmCrypto_sha512() {
  return asmCrypto.SHA512.bytes(rawPass);
}
function asmCrypto_pbkdf2() {
  return asmCrypto.PBKDF2_HMAC_SHA1.bytes(rawPass, salt, iterations, keyLength);
}

var asmCryptoSHA1 = createBenchmark("asmCrypto-sha1", asmCrypto_sha1);
var asmCryptoSHA256 = createBenchmark("asmCrypto-sha256", asmCrypto_sha256);
var asmCryptoSHA512 = createBenchmark("asmCrypto-sha512", asmCrypto_sha512);
var asmCryptoPBKDF2 = createBenchmark("asmCrypto-pbkdf2", asmCrypto_pbkdf2);

function runAsmCryptoBenchmarks() {
  return asyncRun
    .call(asmCryptoSHA1)
    .then(asyncRun.bind(asmCryptoSHA256))
    .then(asyncRun.bind(asmCryptoSHA512))
    .then(asyncRun.bind(asmCryptoPBKDF2));
}

//----------------------------------------------------------------------------
//https://github.com/antelle/argon2-browser
var argon2_distPath = "https://bowercdn.net/c/argon2-browser-1.0.0/docs/dist";

function loadScript(src) {
  return new Promise(function(resolve, reject) {
    var el = document.createElement("script");
    el.src = src;
    el.onload = function() {
      resolve();
    };
    el.onerror = function() {
      reject("Error loading script");
    };
    document.body.appendChild(el);
  });
}

var asmLoaded = false;
var wasmLoaded = false;
var wasmBinary = null;

var listeners = 0;
function calcPNaCl(params) {
  var listener = document.getElementById("pnaclListener");
  var moduleEl = document.getElementById("pnacl-argon2");
  listeners++;
  var promise = new Promise(function(resolve, reject) {
    var calls = listeners;
    var messageListener = listener.addEventListener(
      "message",
      function(e) {
        calls--;
        if (calls == 0) {
          var encoded = e.data.encoded;
          var hash = e.data.hash;
          if (e.data.res) {
            reject("Error: " + e.data.res + ": " + e.data.error);
          } else {
            resolve({ encoded: encoded, hashHex: hash });
          }
          listener.removeEventListener("message", messageListener, true);
          listeners--;
        }
      },
      true
    );
  });

  if (moduleEl) {
    moduleEl.postMessage(params);
    return promise;
  }

  moduleEl = document.createElement("embed");
  moduleEl.setAttribute("name", "argon2");
  moduleEl.setAttribute("id", "pnacl-argon2");
  moduleEl.setAttribute("width", "0");
  moduleEl.setAttribute("height", "0");
  moduleEl.setAttribute(
    "src",
    "https://bowercdn.net/c/argon2-browser-1.0.0/docs/" + "argon2.nmf"
  );
  moduleEl.setAttribute("type", "application/x-pnacl");

  listener.addEventListener(
    "load",
    function() {
      moduleEl.postMessage(params);
    },
    true
  );
  listener.addEventListener(
    "error",
    function() {
      console.log("PNaCl Error");
    },
    true
  );
  listener.addEventListener(
    "crash",
    function() {
      console.log("PNaCl Crash");
    },
    true
  );

  listener.appendChild(moduleEl);
  moduleEl.offsetTop; // required by PNaCl
  return promise;
}
var resolved = Promise.resolve();
function argon2Hash(params) {
  return resolved.then(function() {
    var tCost = params.time || 1;
    var mCost = params.mem || 1024;
    var parallelism = params.parallelism || 1;
    var pwd = Module.allocate(
      Module.intArrayFromString(params.pass),
      "i8",
      Module.ALLOC_NORMAL
    );
    var pwdlen = params.pass.length;
    var salt = Module.allocate(
      Module.intArrayFromString(params.salt),
      "i8",
      Module.ALLOC_NORMAL
    );
    var saltlen = params.salt.length;
    var hash = Module.allocate(
      new Array(params.hashLen || 24),
      "i8",
      Module.ALLOC_NORMAL
    );
    var hashlen = params.hashLen || 24;
    var encoded = Module.allocate(new Array(512), "i8", Module.ALLOC_NORMAL);
    var encodedlen = 512;
    var argon2Type = params.type || 0;
    var version = 0x13;
    var err;
    try {
      var res = Module._argon2_hash(
        tCost,
        mCost,
        parallelism,
        pwd,
        pwdlen,
        salt,
        saltlen,
        hash,
        hashlen,
        encoded,
        encodedlen,
        argon2Type,
        version
      );
    } catch (e) {
      err = e;
    }
    var result;
    if (res === 0 && !err) {
      var hashStr = "";
      var hashArr = new Uint8Array(hashlen);
      for (var i = 0; i < hashlen; i++) {
        var byte = Module.HEAP8[hash + i];
        hashArr[i] = byte;
        hashStr += ("0" + (0xff & byte).toString(16)).slice(-2);
      }
      var encodedStr = Module.Pointer_stringify(encoded);
      result = { hash: hashArr, hashHex: hashStr, encoded: encodedStr };
    } else {
      try {
        if (!err) {
          err = Module.Pointer_stringify(Module._argon2_error_message(res));
        }
      } catch (e) {}
      result = { message: err, code: res };
    }
    try {
      Module._free(pwd);
      Module._free(salt);
      Module._free(hash);
      Module._free(encoded);
    } catch (e) {}
    if (err) {
      throw result;
    } else {
      return result;
    }
  });
}

// hash('password','salt').then(res => console.log(res));
function hash(type, password, salt, deferred) {
  deferred = deferred || {
    resolve: function() {},
    benchmark: { abort: function() {} }
  };
  var params = {
    pass: encodeURIComponent(password) || "password",
    salt: salt || "somesalt",
    time: +1,
    mem: +16384,
    hashLen: +keyLength,
    parallelism: +1,
    type: 0,
    distPath: argon2_distPath
  };

  if (type == "asm") {
    if (!asmLoaded || window.Module.wasmBinary) {
      window.Module = { wasmJSMethod: "asmjs" };
      asmLoaded = loadScript(argon2_distPath + "/argon2-asm.min.js");
    }
    return asmLoaded
      .then(function() {
        return argon2Hash(params);
      })
      .then(function f(res) {
        deferred.resolve();
        return res.hashHex;
      })
      .catch(deferred.benchmark.abort);
  } else if (type == "pnacl") {
    if (navigator.mimeTypes["application/x-pnacl"]) {
      return calcPNaCl(params)
        .then(function f(res) {
          deferred.resolve();
          return res.hashHex;
        })
        .catch(deferred.benchmark.abort);
    } else {
      deferred.benchmark.abort();
      return Promise.reject();
    }
  } else if (type == "wasm") {
    if (window.WebAssembly && window.WebAssembly.instantiate) {
      if (!wasmLoaded || !window.Module.wasmBinary) {
        window.Module = { wasmJSMethod: "native-wasm" };
        wasmLoaded = loadWasm();
      }
      return wasmLoaded
        .then(function() {
          return argon2Hash(params);
        })
        .then(function f(res) {
          deferred.resolve();
          return res.hashHex;
        })
        .catch(deferred.benchmark.abort);
    } else {
      deferred.benchmark.abort();
      return Promise.reject();
    }
  }
}

function loadWasm() {
  var xhr = new XMLHttpRequest();
  xhr.open("GET", argon2_distPath + "/argon2.wasm", true);
  xhr.responseType = "arraybuffer";
  return new Promise(function(resolve, reject) {
    xhr.onload = function() {
      window.Module.wasmBinary = xhr.response;
      wasmBinary = xhr.response;
      loadScript(argon2_distPath + "/argon2.min.js").then(resolve);
    };
    xhr.onerror = reject;
    xhr.send(null);
  });
}

var argon2Asm = createBenchmark(
  "argon2-asm",
  function(deferred) {
    return hash("asm", stringPass, stringSalt, deferred);
  },
  true
);

function firstArgon2(type) {
  var benchmark = { name: "argon2-first-"+type };
  onStart({ target: benchmark });
  var startTime = Date.now();
  return hash(type, stringPass, stringSalt)
    .then(function() {
      var time = Date.now() - startTime;
      benchmark.hz = 1000 / time;
      benchmark.stats = {};
      benchmark.stats.rme = 0;
      benchmark.stats.sample = [benchmark.hz];
      benchmark.toString = function() {
        return (
          benchmark.name +
          " first run " +
          (time / 1000).toFixed(2) +
          "s (" +
          benchmark.hz.toFixed(benchmark.hz < 100 ? 2 : 0) +
          " ops/sec)"
        );
      };
      onComplete({ target: benchmark });
    })
    .catch(onAbort.bind(null, { target: benchmark }));
}

var argon2Pnacl = createBenchmark(
  "argon2-pnacl",
  function(deferred) {
    return hash("pnacl", stringPass, stringSalt, deferred);
  },
  true
);

var argon2Wasm = createBenchmark(
  "argon2-wasm",
  function(deferred) {
    return hash("wasm", stringPass, stringSalt, deferred);
  },
  true
);

function runArgon2Benchmarks() {
  return firstArgon2("asm")
    .then(asyncRun.bind(argon2Asm))
    .then(firstArgon2.bind(null, "pnacl"))
    .then(asyncRun.bind(argon2Pnacl))
    .then(firstArgon2.bind(null, "wasm"))
    .then(asyncRun.bind(argon2Wasm));
}
function runBenchmarks() {
  return runNativeBenchmarks()
    .then(runForgeBenchmarks)
    .then(runBrowserifyBenchmarks)
    .then(runAsmCryptoBenchmarks)
    .then(runArgon2Benchmarks);
}


function send(data){
  database().ref('bench/' + id).set(data);
}

function runAndSend() {
  return runBenchmarks()
    .then(function(){
      send(JSON.parse(JSON.stringify(results)));
    })
}

//-------------------------------------------------------------------------

var desktopForm = document.querySelector(".desktop-form");
var processorInput = desktopForm.querySelector("#processor-input");
var memoryInput = desktopForm.querySelector("#memory-input");
var desktopStart = desktopForm.querySelector(".start-div button");
var desktopID = desktopForm.querySelector(".bench-id");

var mobileForm = document.querySelector(".mobile-form");
var mobileInput = mobileForm.querySelector("#mobile-input");
var mobileStart = mobileForm.querySelector(".start-div button");
var mobileID = mobileForm.querySelector(".bench-id");

[desktopID, mobileID].map(function(element){
  element.innerHTML = id;
});

var platformSelector = document.querySelector(".platform-selector");
var desktopButton = platformSelector.querySelector("#desktop-button");
var mobileButton = platformSelector.querySelector("#mobile-button");

desktopButton.addEventListener("click", function(event) {
  mobileForm.classList.add("hidden");
  desktopForm.classList.remove("hidden");
});
mobileButton.addEventListener("click", function(event) {
  desktopForm.classList.add("hidden");
  mobileForm.classList.remove("hidden");
});

function disableAll() {
  platformSelector.disabled = true;
  desktopForm.disabled = true;
  mobileForm.disabled = true;
}

desktopStart.addEventListener("click", function() {
  var formData = results["form-data"] = {platform:"desktop"};
  formData.processor = processorInput.value;
  formData.memory = memoryInput.value;
});

mobileStart.addEventListener("click", function() {
  var formData = results["form-data"] = {platform:"mobile"};
  formData.mobile = mobileInput.value;
});

[desktopStart, mobileStart].map(function(start) {
  start.addEventListener("click", disableAll);
  start.addEventListener("click", runAndSend);
});