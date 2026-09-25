// What the Gryt app would have to provide under Hermes: a CSPRNG-backed getRandomValues,
// performance.now and TextDecoder. Here they come from the JSI host instead of Expo.
var __timerQueue = []
globalThis.__runTimers = function () {
  if (!__timerQueue.length) return false
  var due = __timerQueue
  __timerQueue = []
  for (var i = 0; i < due.length; i++) due[i]()
  return true
}
globalThis.setTimeout = function (f) { __timerQueue.push(f); return __timerQueue.length }
globalThis.performance = { now: function () { return __hostNow() } }
globalThis.crypto = {
  getRandomValues: function (a) { __hostRandom(a.buffer, a.byteOffset, a.byteLength); return a },
}
if (typeof TextDecoder === "undefined") {
  globalThis.TextDecoder = function () {}
  globalThis.TextDecoder.prototype.decode = function (b) {
    var s = ""
    for (var i = 0; i < (b ? b.length : 0); i++) s += "%" + b[i].toString(16).padStart(2, "0")
    return decodeURIComponent(s)
  }
}
globalThis.console = { log: function () { print(Array.prototype.join.call(arguments, " ")) }, error: function () { print(Array.prototype.join.call(arguments, " ")) } }
