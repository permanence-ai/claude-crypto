// SPDX-License-Identifier: Apache-2.0

#pragma once

// Zero-dependency pluggable logging hook for safe-crypto-lib.
//
// Usage:
//   crypto_set_log_sink([](CryptoLogLevel lvl, std::string_view msg) {
//       my_logger.log(lvl, msg);
//   }, CryptoLogLevel::Debug);
//
// The library emits Debug messages at operation entry and success,
// and Error messages at every failure return.  Key material, IVs,
// and payload bytes are never included in log messages.
//
// Default state: no sink registered, all logging is a no-op.
// Thread-safe: crypto_set_log_sink is safe to call once before spawning
// worker threads.  crypto_log uses a mutex for the fn pointer and a
// separate atomic for the fast-path threshold check.

#include <atomic>
#include <cstddef>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>


enum class CryptoLogLevel : int {
    Debug = 0,
    Info  = 1,
    Warn  = 2,
    Error = 3,
    Off   = 4,
};

using CryptoLogSink = std::function<void(CryptoLogLevel, std::string_view)>;


namespace crypto_log_detail {

// Build "op: key=val[, key=val...]" strings without <format> or {fmt}.
// Returns a std::string so callers can wrap the call in crypto_log_enabled guard.
inline auto msg(std::string_view op, std::string_view k1, std::size_t v1) -> std::string {
    return std::string(op) + ": " + std::string(k1) + "=" + std::to_string(v1) + " bytes";
}
inline auto msg(std::string_view op, std::string_view k1, std::size_t v1,
                                     std::string_view k2, std::size_t v2) -> std::string {
    return std::string(op) + ": " + std::string(k1) + "=" + std::to_string(v1)
         + " bytes, " + std::string(k2) + "=" + std::to_string(v2) + " bytes";
}
inline auto msg(std::string_view op, std::string_view k1, std::size_t v1,
                                     std::string_view k2, std::size_t v2,
                                     std::string_view k3, std::size_t v3) -> std::string {
    return std::string(op) + ": " + std::string(k1) + "=" + std::to_string(v1)
         + " bytes, " + std::string(k2) + "=" + std::to_string(v2)
         + " bytes, " + std::string(k3) + "=" + std::to_string(v3) + " bytes";
}

struct LogState {
    std::mutex       mu;
    CryptoLogSink    fn;
    std::atomic<int> threshold{static_cast<int>(CryptoLogLevel::Off)};
};

inline auto state() noexcept -> LogState& {
    static LogState s;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
    return s;
}

} // namespace crypto_log_detail


// Register a sink callable and a minimum log level.
// Passing nullptr (or an empty function) disables logging.
// Intended to be called once at startup before any library operations.
inline void crypto_set_log_sink(CryptoLogSink sink,
                                CryptoLogLevel threshold = CryptoLogLevel::Debug)
{
    auto& s = crypto_log_detail::state();
    const int thr = sink ? static_cast<int>(threshold)
                         : static_cast<int>(CryptoLogLevel::Off);
    {
        std::lock_guard lock(s.mu);
        s.fn = std::move(sink);
    }
    // Store threshold after fn is visible so threads that observe threshold != Off
    // will always find a valid fn under the mutex.
    s.threshold.store(thr, std::memory_order_release);
}

// Fast predicate for guarding dynamic message construction.
// Wrapping expensive formatting in: if (crypto_log_enabled(L)) { crypto_log(L, msg()); }
// avoids string allocation on the hot path when logging is off.
[[nodiscard]]
inline bool crypto_log_enabled(CryptoLogLevel level) noexcept {
    return crypto_log_detail::state().threshold.load(std::memory_order_relaxed)
           <= static_cast<int>(level);
}

// Emit a log message.  No-op if no sink is registered or level < threshold.
// String literals can be passed without the crypto_log_enabled guard since
// no allocation occurs and the threshold check inside is a single atomic load.
inline void crypto_log(CryptoLogLevel level, std::string_view msg) {
    auto& s = crypto_log_detail::state();
    if (s.threshold.load(std::memory_order_acquire) > static_cast<int>(level)) { return; }
    std::lock_guard lock(s.mu);
    if (s.fn) { s.fn(level, msg); }
}
