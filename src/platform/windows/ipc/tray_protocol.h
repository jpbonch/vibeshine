/**
 * @file src/platform/windows/ipc/tray_protocol.h
 * @brief IPC protocol shared between Sunshine and the Windows tray helper.
 */
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace platf::tray_ipc {
  constexpr const char *kPipeName = "vibeshine_tray";
  constexpr const char *kActionPipeName = "vibeshine_tray_action";

  enum class MsgType : uint8_t {
    Action = 1,  ///< Helper -> Sunshine: action request.
    StreamState = 2,  ///< Sunshine -> Helper: stream state update (with optional notify).
    NotifyPin = 3,  ///< Sunshine -> Helper: pairing PIN notification.
    NotifyVigem = 4,  ///< Sunshine -> Helper: ViGEm missing notification.
    NotifyGeneric = 5,  ///< Sunshine -> Helper: generic notification.
    Shutdown = 6,  ///< Sunshine -> Helper: graceful shutdown.
    Ping = 0xFE,  ///< Bidirectional ping (optional).
    Pong = 0xFF  ///< Bidirectional pong (optional).
  };

  enum class TrayAction : uint8_t {
    None = 0,
    OpenUi = 1,
    CheckUpdate = 2,
    Restart = 3,
    Quit = 4,
    OpenReleasePage = 5
  };

  enum class StreamState : uint8_t {
    Idle = 0,
    Playing = 1,
    Pausing = 2,
    Stopped = 3
  };

  inline void append_u32(std::vector<uint8_t> &out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFFu));
  }

  inline bool consume_u32(std::span<const uint8_t> &payload, uint32_t &value_out) {
    if (payload.size() < 4) {
      return false;
    }
    value_out = static_cast<uint32_t>(payload[0]) |
                (static_cast<uint32_t>(payload[1]) << 8) |
                (static_cast<uint32_t>(payload[2]) << 16) |
                (static_cast<uint32_t>(payload[3]) << 24);
    payload = payload.subspan(4);
    return true;
  }

  inline void append_string(std::vector<uint8_t> &out, std::string_view value) {
    append_u32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
  }

  inline bool consume_string(std::span<const uint8_t> &payload, std::string &value_out) {
    uint32_t len = 0;
    if (!consume_u32(payload, len)) {
      return false;
    }
    if (payload.size() < len) {
      return false;
    }
    if (len == 0) {
      value_out.clear();
      return true;
    }
    value_out.assign(reinterpret_cast<const char *>(payload.data()), len);
    payload = payload.subspan(len);
    return true;
  }
}  // namespace platf::tray_ipc
