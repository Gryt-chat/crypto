// Minimal JSI host: runs one JS file in the Hermes VM that React Native ships, with just
// print, a monotonic clock, random bytes and a timer queue. Usage: hermes-host bundle.js
#include <hermes/hermes.h>
#include <jsi/jsi.h>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace facebook::jsi;

static void fn(Runtime& rt, const char* name, unsigned n, HostFunctionType f) {
  rt.global().setProperty(rt, name, Function::createFromHostFunction(rt, PropNameID::forAscii(rt, name), n, std::move(f)));
}

int main(int argc, char** argv) {
  if (argc < 2) { std::cerr << "usage: hermes-host bundle.js\n"; return 2; }
  std::ifstream in(argv[1]);
  std::stringstream src; src << in.rdbuf();

  auto config = ::hermes::vm::RuntimeConfig::Builder().withMicrotaskQueue(true).build();
  auto rt = facebook::hermes::makeHermesRuntime(config);
  Runtime& r = *rt;

  fn(r, "print", 1, [](Runtime& rt, const Value&, const Value* a, size_t n) {
    std::cout << (n ? a[0].toString(rt).utf8(rt) : "") << std::endl;
    return Value::undefined();
  });
  fn(r, "__hostNow", 0, [](Runtime&, const Value&, const Value*, size_t) {
    using namespace std::chrono;
    return Value(duration<double, std::milli>(steady_clock::now().time_since_epoch()).count());
  });
  fn(r, "__hostRandom", 3, [](Runtime& rt, const Value&, const Value* a, size_t) {
    auto buf = a[0].asObject(rt).getArrayBuffer(rt);
    size_t off = (size_t)a[1].asNumber(), len = (size_t)a[2].asNumber();
    arc4random_buf(buf.data(rt) + off, len);
    return Value::undefined();
  });

  try {
    r.evaluateJavaScript(std::make_shared<StringBuffer>(src.str()), argv[1]);
    auto runTimers = r.global().getPropertyAsFunction(r, "__runTimers");
    for (;;) {
      r.drainMicrotasks();
      if (!runTimers.call(r).getBool()) { r.drainMicrotasks(); break; }
    }
    auto code = r.global().getProperty(r, "__exitCode");
    return code.isNumber() ? (int)code.asNumber() : 0;
  } catch (const JSError& e) {
    std::cerr << "JSError: " << e.getMessage() << "\n" << e.getStack() << std::endl;
    return 1;
  } catch (const JSIException& e) {
    std::cerr << "JSIException: " << e.what() << std::endl;
    return 1;
  }
}
