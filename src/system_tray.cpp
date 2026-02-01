/**
 * @file src/system_tray.cpp
 * @brief Definitions for the system tray icon and notification system.
 */
// macros
#if defined SUNSHINE_TRAY && SUNSHINE_TRAY >= 1

#if defined(_WIN32)
  #define WIN32_LEAN_AND_MEAN
  #include <Windows.h>
  #include <accctrl.h>
  #include <aclapi.h>

  // standard includes
  #include <array>
  #include <atomic>
  #include <chrono>
  #include <cstring>
  #include <filesystem>
  #include <memory>
  #include <mutex>
  #include <optional>
  #include <string>
  #include <string_view>
  #include <thread>
  #include <vector>

  // local includes
  #include "entry_handler.h"
  #include "logging.h"
  #include "platform/common.h"
  #include "process.h"
  #include "src/platform/windows/misc.h"
  #include "src/platform/windows/ipc/misc_utils.h"
  #include "src/platform/windows/ipc/pipes.h"
  #include "src/platform/windows/ipc/process_handler.h"
  #include "src/platform/windows/ipc/tray_protocol.h"
  #include "update.h"
  #include "utility.h"

using namespace std::literals;

namespace system_tray {
  void tray_open_ui_cb([[maybe_unused]] struct tray_menu *item);
  void tray_restart_cb([[maybe_unused]] struct tray_menu *item);
  void tray_quit_cb([[maybe_unused]] struct tray_menu *item);

  namespace {
    using namespace platf::tray_ipc;

    constexpr int kServerConnectTimeoutMs = 15000;
    constexpr auto kServerRetryDelay = std::chrono::milliseconds(750);

    struct CachedState {
      StreamState state {StreamState::Idle};
      std::string app_name;
      bool valid {false};
    };

    std::mutex &pipe_mutex() {
      static std::mutex m;
      return m;
    }

    std::shared_ptr<platf::dxgi::AsyncNamedPipe> &pipe_shared() {
      static std::shared_ptr<platf::dxgi::AsyncNamedPipe> pipe;
      return pipe;
    }

    std::mutex &state_mutex() {
      static std::mutex m;
      return m;
    }

    CachedState &cached_state() {
      static CachedState state;
      return state;
    }

    std::atomic<bool> &tray_server_running() {
      static std::atomic<bool> running {false};
      return running;
    }

    std::jthread &tray_server_thread() {
      static std::jthread thread;
      return thread;
    }

    std::jthread &tray_action_thread() {
      static std::jthread thread;
      return thread;
    }

    bool build_admin_only_sd(SECURITY_DESCRIPTOR &desc, PACL *out_pacl) {
      if (!out_pacl) {
        return false;
      }
      *out_pacl = nullptr;

      if (!InitializeSecurityDescriptor(&desc, SECURITY_DESCRIPTOR_REVISION)) {
        return false;
      }

      SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
      PSID admins_sid = nullptr;
      if (!AllocateAndInitializeSid(
            &nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &admins_sid)) {
        return false;
      }
      auto free_admins_sid = util::fail_guard([&]() {
        if (admins_sid) {
          FreeSid(admins_sid);
        }
      });

      PSID system_sid = nullptr;
      if (!AllocateAndInitializeSid(
            &nt_authority,
            1,
            SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0,
            &system_sid)) {
        return false;
      }
      auto free_system_sid = util::fail_guard([&]() {
        if (system_sid) {
          FreeSid(system_sid);
        }
      });

      EXPLICIT_ACCESS entries[2] = {};
      entries[0].grfAccessPermissions = GENERIC_ALL;
      entries[0].grfAccessMode = SET_ACCESS;
      entries[0].grfInheritance = NO_INHERITANCE;
      entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
      entries[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
      entries[0].Trustee.ptstrName = static_cast<LPTSTR>(system_sid);

      entries[1] = entries[0];
      entries[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
      entries[1].Trustee.ptstrName = static_cast<LPTSTR>(admins_sid);

      PACL dacl = nullptr;
      DWORD err = SetEntriesInAcl(2, entries, nullptr, &dacl);
      if (err != ERROR_SUCCESS) {
        return false;
      }

      if (!SetSecurityDescriptorDacl(&desc, TRUE, dacl, FALSE)) {
        LocalFree(dacl);
        return false;
      }

      *out_pacl = dacl;
      return true;
    }

    ProcessHandler &helper_proc() {
      static ProcessHandler handler(/*use_job=*/false);
      return handler;
    }

    bool user_session_ready() {
      HANDLE token = platf::dxgi::retrieve_users_token(false);
      if (!token) {
        return false;
      }
      CloseHandle(token);
      return true;
    }

    std::filesystem::path tray_helper_path() {
      wchar_t module_path[MAX_PATH] = {};
      if (!GetModuleFileNameW(nullptr, module_path, _countof(module_path))) {
        return {};
      }
      std::filesystem::path exe_path(module_path);
      auto dir = exe_path.parent_path();
      return dir / L"tools" / L"vibeshine_tray.exe";
    }

    bool ensure_helper_started() {
      if (!user_session_ready()) {
        return false;
      }

      const auto helper = tray_helper_path();
      if (helper.empty()) {
        BOOST_LOG(error) << "Tray helper path could not be resolved";
        return false;
      }
      if (!std::filesystem::exists(helper)) {
        BOOST_LOG(warning) << "Tray helper not found at: " << platf::to_utf8(helper.wstring());
        return false;
      }

      if (platf::dxgi::is_process_running(L"vibeshine_tray.exe")) {
        return true;
      }

      bool started = helper_proc().start(helper.wstring(), L"", false);
      if (!started && helper_proc().get_process_handle()) {
        return true;
      }
      if (!started) {
        BOOST_LOG(error) << "Failed to start tray helper: " << platf::to_utf8(helper.wstring());
      }
      return started;
    }

    void send_message(MsgType type, const std::vector<uint8_t> &payload) {
      std::shared_ptr<platf::dxgi::AsyncNamedPipe> pipe;
      {
        std::lock_guard<std::mutex> lg(pipe_mutex());
        pipe = pipe_shared();
      }
      if (!pipe || !pipe->is_connected()) {
        return;
      }

      std::vector<uint8_t> out(1 + payload.size());
      out[0] = static_cast<uint8_t>(type);
      if (!payload.empty()) {
        std::memcpy(out.data() + 1, payload.data(), payload.size());
      }
      pipe->send(out);
    }

    void send_stream_state(StreamState state, std::string_view app_name, bool notify) {
      std::vector<uint8_t> payload(2 + app_name.size());
      payload[0] = static_cast<uint8_t>(state);
      payload[1] = notify ? 1u : 0u;
      if (!app_name.empty()) {
        std::memcpy(payload.data() + 2, app_name.data(), app_name.size());
      }
      send_message(MsgType::StreamState, payload);
    }

    void send_notify_generic(std::string_view title, std::string_view text, TrayAction action) {
      const auto total = 1 + title.size() + 1 + text.size();
      std::vector<uint8_t> payload(total);
      payload[0] = static_cast<uint8_t>(action);
      if (!title.empty()) {
        std::memcpy(payload.data() + 1, title.data(), title.size());
      }
      payload[1 + title.size()] = '\0';
      if (!text.empty()) {
        std::memcpy(payload.data() + 1 + title.size() + 1, text.data(), text.size());
      }
      send_message(MsgType::NotifyGeneric, payload);
    }

    void send_notify_pin() {
      send_message(MsgType::NotifyPin, {});
    }

    void send_notify_vigem() {
      send_message(MsgType::NotifyVigem, {});
    }

    void send_shutdown() {
      send_message(MsgType::Shutdown, {});
    }

    void handle_action(TrayAction action, const std::string &path) {
      switch (action) {
        case TrayAction::OpenUi:
          if (path.empty()) {
            launch_ui();
          } else {
            launch_ui(std::optional<std::string> {path});
          }
          break;
        case TrayAction::CheckUpdate:
          update::trigger_check(true);
          break;
        case TrayAction::Restart:
          platf::restart();
          break;
        case TrayAction::Quit:
          tray_quit_cb(nullptr);
          break;
        case TrayAction::OpenReleasePage:
          update::open_last_notified_release_page();
          break;
        case TrayAction::None:
        default:
          break;
      }
    }

    void process_message(std::span<const uint8_t> bytes) {
      if (bytes.empty()) {
        return;
      }
      auto type = static_cast<MsgType>(bytes[0]);
      std::span<const uint8_t> payload = bytes.subspan(1);

      if (type == MsgType::Action) {
        if (payload.empty()) {
          return;
        }
        auto action = static_cast<TrayAction>(payload[0]);
        payload = payload.subspan(1);
        std::string path;
        if (!payload.empty()) {
          path.assign(reinterpret_cast<const char *>(payload.data()), payload.size());
        }
        handle_action(action, path);
      } else if (type == MsgType::Ping) {
        send_message(MsgType::Pong, {});
      }
    }

    void send_cached_state_if_any() {
      CachedState cached;
      {
        std::lock_guard<std::mutex> lg(state_mutex());
        cached = cached_state();
      }
      if (!cached.valid) {
        return;
      }
      send_stream_state(cached.state, cached.app_name, false);
    }

    void tray_server_loop(std::stop_token stop_token) {
      while (!stop_token.stop_requested()) {
        if (!ensure_helper_started()) {
          std::this_thread::sleep_for(kServerRetryDelay);
          continue;
        }

        platf::dxgi::FramedPipeFactory anon_factory(std::make_unique<platf::dxgi::AnonymousPipeFactory>());
        auto pipe = anon_factory.create_server(kPipeName);
        if (!pipe) {
          platf::dxgi::FramedPipeFactory fallback_factory(std::make_unique<platf::dxgi::NamedPipeFactory>());
          pipe = fallback_factory.create_server(kPipeName);
          if (!pipe) {
            BOOST_LOG(error) << "Tray IPC: failed to create server pipe";
            std::this_thread::sleep_for(kServerRetryDelay);
            continue;
          }
        }

        auto async_pipe = std::make_shared<platf::dxgi::AsyncNamedPipe>(std::move(pipe));
        async_pipe->wait_for_client_connection(kServerConnectTimeoutMs);
        if (!async_pipe->is_connected()) {
          continue;
        }

        {
          std::lock_guard<std::mutex> lg(pipe_mutex());
          pipe_shared() = async_pipe;
        }

        auto on_message = [](std::span<const uint8_t> msg) {
          process_message(msg);
        };
        auto on_error = [](const std::string &err) {
          BOOST_LOG(error) << "Tray IPC error: " << err;
        };
        auto on_broken = []() {
          BOOST_LOG(warning) << "Tray IPC: client disconnected";
        };

        async_pipe->start(on_message, on_error, on_broken);
        send_cached_state_if_any();

        while (!stop_token.stop_requested() && async_pipe->is_connected()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        async_pipe->stop();

        {
          std::lock_guard<std::mutex> lg(pipe_mutex());
          if (pipe_shared() == async_pipe) {
            pipe_shared().reset();
          }
        }
      }
    }

    void tray_action_server_loop(std::stop_token stop_token) {
      while (!stop_token.stop_requested()) {
        if (!ensure_helper_started()) {
          std::this_thread::sleep_for(kServerRetryDelay);
          continue;
        }

        auto base_factory = std::make_unique<platf::dxgi::NamedPipeFactory>();
        base_factory->set_security_descriptor_builder(build_admin_only_sd);
        platf::dxgi::FramedPipeFactory factory(std::move(base_factory));
        auto pipe = factory.create_server(kActionPipeName);
        if (!pipe) {
          BOOST_LOG(error) << "Tray IPC: failed to create action pipe";
          std::this_thread::sleep_for(kServerRetryDelay);
          continue;
        }

        pipe->wait_for_client_connection(kServerConnectTimeoutMs);
        if (!pipe->is_connected()) {
          continue;
        }

        std::array<uint8_t, 4096> buffer {};
        size_t bytes_read = 0;
        const auto result = pipe->receive(buffer, bytes_read, 5000);
        if (result == platf::dxgi::PipeResult::Success && bytes_read > 0) {
          process_message(std::span<const uint8_t>(buffer.data(), bytes_read));
        }

        pipe->disconnect();
      }
    }

    void stop_helper_process() {
      HANDLE handle = helper_proc().get_process_handle();
      if (!handle) {
        return;
      }
      const DWORD wait_result = WaitForSingleObject(handle, 1500);
      if (wait_result == WAIT_TIMEOUT) {
        helper_proc().terminate();
      }
    }
  }  // namespace

  void tray_open_ui_cb([[maybe_unused]] struct tray_menu *item) {
    BOOST_LOG(info) << "Opening UI from system tray"sv;
    launch_ui();
  }

  void tray_restart_cb([[maybe_unused]] struct tray_menu *item) {
    BOOST_LOG(info) << "Restarting from system tray"sv;
    platf::restart();
  }

  void tray_quit_cb([[maybe_unused]] struct tray_menu *item) {
    BOOST_LOG(info) << "Quitting from system tray"sv;

    // If we're running in a service, return a special status to
    // tell it to terminate too, otherwise it will just respawn us.
    if (GetConsoleWindow() == nullptr) {
      lifetime::exit_sunshine(ERROR_SHUTDOWN_IN_PROGRESS, true);
      return;
    }

    lifetime::exit_sunshine(0, true);
  }

  int system_tray() {
    return 0;
  }

  void run_tray() {
    if (tray_server_running().exchange(true)) {
      return;
    }

    auto &thread = tray_server_thread();
    if (thread.joinable()) {
      thread.request_stop();
      thread.join();
    }

    thread = std::jthread([](std::stop_token stop_token) {
      tray_server_loop(stop_token);
    });

    auto &action_thread = tray_action_thread();
    if (action_thread.joinable()) {
      action_thread.request_stop();
      action_thread.join();
    }
    action_thread = std::jthread([](std::stop_token stop_token) {
      tray_action_server_loop(stop_token);
    });
  }

  int end_tray() {
    if (!tray_server_running().exchange(false)) {
      return 0;
    }

    send_shutdown();

    auto &action_thread = tray_action_thread();
    if (action_thread.joinable()) {
      action_thread.request_stop();
      action_thread.join();
    }

    auto &thread = tray_server_thread();
    if (thread.joinable()) {
      thread.request_stop();
      thread.join();
    }

    stop_helper_process();
    return 0;
  }

  void update_tray_playing(std::string app_name) {
    {
      std::lock_guard<std::mutex> lg(state_mutex());
      cached_state().state = StreamState::Playing;
      cached_state().app_name = app_name;
      cached_state().valid = true;
    }
    if (!tray_server_running().load()) {
      return;
    }
    send_stream_state(StreamState::Playing, app_name, true);
  }

  void update_tray_pausing(std::string app_name) {
    {
      std::lock_guard<std::mutex> lg(state_mutex());
      cached_state().state = StreamState::Pausing;
      cached_state().app_name = app_name;
      cached_state().valid = true;
    }
    if (!tray_server_running().load()) {
      return;
    }
    send_stream_state(StreamState::Pausing, app_name, true);
  }

  void update_tray_stopped(std::string app_name) {
    {
      std::lock_guard<std::mutex> lg(state_mutex());
      cached_state().state = StreamState::Stopped;
      cached_state().app_name = app_name;
      cached_state().valid = true;
    }
    if (!tray_server_running().load()) {
      return;
    }
    send_stream_state(StreamState::Stopped, app_name, true);
  }

  void update_tray_require_pin() {
    if (!tray_server_running().load()) {
      return;
    }
    send_notify_pin();
  }

  void update_tray_vigem_missing() {
    if (!tray_server_running().load()) {
      return;
    }
    send_notify_vigem();
  }

  void tray_notify(const char *title, const char *text, void (*cb)()) {
    if (!tray_server_running().load()) {
      return;
    }
    TrayAction action = cb ? TrayAction::OpenReleasePage : TrayAction::None;
    send_notify_generic(title ? title : "", text ? text : "", action);
  }
}  // namespace system_tray

#else

  #if defined(_WIN32)
    #define WIN32_LEAN_AND_MEAN
    #include <Windows.h>
    #include <accctrl.h>
    #include <aclapi.h>
    #define TRAY_ICON WEB_DIR "images/sunshine.ico"
    #define TRAY_ICON_PLAYING WEB_DIR "images/sunshine-playing.ico"
    #define TRAY_ICON_PAUSING WEB_DIR "images/sunshine-pausing.ico"
    #define TRAY_ICON_LOCKED WEB_DIR "images/sunshine-locked.ico"
  #elif defined(__linux__) || defined(linux) || defined(__linux)
    #define TRAY_ICON SUNSHINE_TRAY_PREFIX "-tray"
    #define TRAY_ICON_PLAYING SUNSHINE_TRAY_PREFIX "-playing"
    #define TRAY_ICON_PAUSING SUNSHINE_TRAY_PREFIX "-pausing"
    #define TRAY_ICON_LOCKED SUNSHINE_TRAY_PREFIX "-locked"
  #elif defined(__APPLE__) || defined(__MACH__)
    #define TRAY_ICON WEB_DIR "images/logo-sunshine-16.png"
    #define TRAY_ICON_PLAYING WEB_DIR "images/sunshine-playing-16.png"
    #define TRAY_ICON_PAUSING WEB_DIR "images/sunshine-pausing-16.png"
    #define TRAY_ICON_LOCKED WEB_DIR "images/sunshine-locked-16.png"
    #include <dispatch/dispatch.h>
  #endif

  // standard includes
  #include <atomic>
  #include <csignal>
  #include <cwchar>
  #include <string>
  #include <thread>

  // lib includes
  #include <boost/filesystem.hpp>
  #include <tray/src/tray.h>

  // local includes
  #include "confighttp.h"
  #include "logging.h"
  #include "platform/common.h"
  #include "process.h"
  #include "src/entry_handler.h"
  #include "update.h"

using namespace std::literals;

// system_tray namespace
namespace system_tray {
  static std::atomic<bool> tray_initialized = false;

  static void tray_log_bridge(enum tray_log_level level, const char *message) {
    if (!message) {
      return;
    }
    switch (level) {
      case TRAY_LOG_DEBUG:
        BOOST_LOG(debug) << message;
        break;
      case TRAY_LOG_INFO:
        BOOST_LOG(info) << message;
        break;
      case TRAY_LOG_WARNING:
        BOOST_LOG(warning) << message;
        break;
      case TRAY_LOG_ERROR:
        BOOST_LOG(error) << message;
        break;
    }
  }

  void tray_open_ui_cb([[maybe_unused]] struct tray_menu *item) {
    BOOST_LOG(info) << "Opening UI from system tray"sv;
    launch_ui();
  }

  void tray_restart_cb([[maybe_unused]] struct tray_menu *item) {
    BOOST_LOG(info) << "Restarting from system tray"sv;

    platf::restart();
  }

  void tray_quit_cb([[maybe_unused]] struct tray_menu *item) {
    BOOST_LOG(info) << "Quitting from system tray"sv;

  #ifdef _WIN32
    // If we're running in a service, return a special status to
    // tell it to terminate too, otherwise it will just respawn us.
    if (GetConsoleWindow() == nullptr) {
      lifetime::exit_sunshine(ERROR_SHUTDOWN_IN_PROGRESS, true);
      return;
    }
  #endif

    lifetime::exit_sunshine(0, true);
  }

  // Tray menu
  static struct tray tray = {
    .icon = TRAY_ICON,
    .tooltip = PROJECT_NAME,
    .menu =
      (struct tray_menu[]) {
        // todo - use boost/locale to translate menu strings
        {.text = "Open Sunshine", .cb = tray_open_ui_cb},
        {.text = "-"},
        {.text = "Check for Update", .cb = [](tray_menu *) {
           BOOST_LOG(info) << "Manual update check requested from tray"sv;
           update::trigger_check(true);
         }},
        {.text = "Restart", .cb = tray_restart_cb},
        {.text = "Quit", .cb = tray_quit_cb},
        {.text = nullptr}
      },
    .iconPathCount = 4,
    .allIconPaths = {TRAY_ICON, TRAY_ICON_LOCKED, TRAY_ICON_PLAYING, TRAY_ICON_PAUSING},
  };

  int system_tray() {
  #ifdef _WIN32
    // If we're running as SYSTEM, Explorer.exe will not have permission to open our thread handle
    // to monitor for thread termination. If Explorer fails to open our thread, our tray icon
    // will persist forever if we terminate unexpectedly. To avoid this, we will modify our thread
    // DACL to add an ACE that allows SYNCHRONIZE access to Everyone.
    {
      PACL old_dacl;
      PSECURITY_DESCRIPTOR sd;
      auto error = GetSecurityInfo(GetCurrentThread(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &old_dacl, nullptr, &sd);
      if (error != ERROR_SUCCESS) {
        BOOST_LOG(warning) << "GetSecurityInfo() failed: "sv << error;
        return 1;
      }

      auto free_sd = util::fail_guard([sd]() {
        LocalFree(sd);
      });

      SID_IDENTIFIER_AUTHORITY sid_authority = SECURITY_WORLD_SID_AUTHORITY;
      PSID world_sid;
      if (!AllocateAndInitializeSid(&sid_authority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &world_sid)) {
        error = GetLastError();
        BOOST_LOG(warning) << "AllocateAndInitializeSid() failed: "sv << error;
        return 1;
      }

      auto free_sid = util::fail_guard([world_sid]() {
        FreeSid(world_sid);
      });

      EXPLICIT_ACCESS ea {};
      ea.grfAccessPermissions = SYNCHRONIZE;
      ea.grfAccessMode = GRANT_ACCESS;
      ea.grfInheritance = NO_INHERITANCE;
      ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
      ea.Trustee.ptstrName = (LPSTR) world_sid;

      PACL new_dacl;
      error = SetEntriesInAcl(1, &ea, old_dacl, &new_dacl);
      if (error != ERROR_SUCCESS) {
        BOOST_LOG(warning) << "SetEntriesInAcl() failed: "sv << error;
        return 1;
      }

      auto free_new_dacl = util::fail_guard([new_dacl]() {
        LocalFree(new_dacl);
      });

      error = SetSecurityInfo(GetCurrentThread(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, new_dacl, nullptr);
      if (error != ERROR_SUCCESS) {
        BOOST_LOG(warning) << "SetSecurityInfo() failed: "sv << error;
        return 1;
      }
    }

    // Wait for the shell to be initialized before registering the tray icon.
    // This ensures the tray icon works reliably after a logoff/logon cycle.
    while (GetShellWindow() == nullptr) {
      Sleep(1000);
    }

    auto wait_for_default_desktop = []() {
      constexpr int attempts = 60;
      for (int attempt = 0; attempt < attempts; ++attempt) {
        HDESK desktop = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS | DESKTOP_ENUMERATE);
        if (desktop != nullptr) {
          auto close_desktop = util::fail_guard([desktop]() {
            CloseDesktop(desktop);
          });

          WCHAR desktop_name[256] = {};
          DWORD required_length = 0;
          if (GetUserObjectInformationW(desktop, UOI_NAME, desktop_name, sizeof(desktop_name), &required_length)) {
            if (_wcsicmp(desktop_name, L"Default") == 0) {
              return true;
            }
          }
        }

        Sleep(1000);
      }

      return false;
    };

    if (!wait_for_default_desktop()) {
      BOOST_LOG(warning) << "Timed out waiting for interactive desktop; system tray may not appear"sv;
    } else {
      BOOST_LOG(debug) << "Interactive desktop ready for tray initialization"sv;
    }
  #endif

    int attempt = 0;
    int tray_init_result = -1;
    while (tray_init_result < 0 && attempt < 30) {
      tray_init_result = tray_init(&tray);
      if (tray_init_result >= 0) {
        break;
      }
#ifdef _WIN32
      auto last_error = GetLastError();
      BOOST_LOG(warning) << "Failed to create system tray (attempt "sv << attempt + 1 << ", error " << last_error << ')';
#else
      BOOST_LOG(warning) << "Failed to create system tray (attempt "sv << attempt + 1 << ')';
#endif
      std::this_thread::sleep_for(2s);
      ++attempt;
    }

    if (tray_init_result < 0) {
      BOOST_LOG(warning) << "Failed to create system tray after retries"sv;
      return 1;
    } else {
      BOOST_LOG(info) << "System tray created"sv;
    }

    tray_initialized = true;
    while (tray_loop(1) == 0) {
      BOOST_LOG(debug) << "System tray loop"sv;
    }

    return 0;
  }

  void run_tray() {
    // create the system tray
    tray_set_log_callback(&tray_log_bridge);
  #if defined(__APPLE__) || defined(__MACH__)
    // macOS requires that UI elements be created on the main thread
    // creating tray using dispatch queue does not work, although the code doesn't actually throw any (visible) errors

    // dispatch_async(dispatch_get_main_queue(), ^{
    //   system_tray();
    // });

    BOOST_LOG(info) << "system_tray() is not yet implemented for this platform."sv;
  #else  // Windows, Linux
    // create tray in separate thread
    std::thread tray_thread(system_tray);
    tray_thread.detach();
  #endif
  }

  int end_tray() {
    tray_initialized = false;
    tray_exit();
    return 0;
  }

  // Persistent storage for tooltip/notification strings to avoid dangling pointers
  static std::string s_tooltip;
  static std::string s_notification_text;

  void update_tray_playing(std::string app_name) {
    if (!tray_initialized) {
      return;
    }

    tray.notification_title = nullptr;
    tray.notification_text = nullptr;
    tray.notification_cb = nullptr;
    tray.notification_icon = nullptr;
    tray.icon = TRAY_ICON_PLAYING;
    tray_update(&tray);
    tray.icon = TRAY_ICON_PLAYING;
    tray.notification_title = "Stream Started";
    s_notification_text = "Streaming started for " + app_name;
    s_tooltip = s_notification_text;
    tray.notification_text = s_notification_text.c_str();
    tray.tooltip = s_tooltip.c_str();
    tray.notification_icon = TRAY_ICON_PLAYING;
    tray_update(&tray);
  }

  void update_tray_pausing(std::string app_name) {
    if (!tray_initialized) {
      return;
    }

    tray.notification_title = nullptr;
    tray.notification_text = nullptr;
    tray.notification_cb = nullptr;
    tray.notification_icon = nullptr;
    tray.icon = TRAY_ICON_PAUSING;
    tray_update(&tray);
    s_notification_text = "Streaming paused for " + app_name;
    tray.icon = TRAY_ICON_PAUSING;
    tray.notification_title = "Stream Paused";
    tray.notification_text = s_notification_text.c_str();
    tray.tooltip = s_notification_text.c_str();
    tray.notification_icon = TRAY_ICON_PAUSING;
    tray_update(&tray);
  }

  void update_tray_stopped(std::string app_name) {
    if (!tray_initialized) {
      return;
    }

    tray.notification_title = nullptr;
    tray.notification_text = nullptr;
    tray.notification_cb = nullptr;
    tray.notification_icon = nullptr;
    tray.icon = TRAY_ICON;
    tray_update(&tray);
    s_notification_text = "Application " + app_name + " successfully stopped";
    tray.icon = TRAY_ICON;
    tray.notification_icon = TRAY_ICON;
    tray.notification_title = "Application Stopped";
    tray.notification_text = s_notification_text.c_str();
    tray.tooltip = PROJECT_NAME;
    tray_update(&tray);
  }

  void update_tray_require_pin() {
    if (!tray_initialized) {
      return;
    }

    tray.notification_title = nullptr;
    tray.notification_text = nullptr;
    tray.notification_cb = nullptr;
    tray.notification_icon = nullptr;
    tray.icon = TRAY_ICON;
    tray_update(&tray);
    tray.icon = TRAY_ICON;
    tray.notification_title = "Incoming Pairing Request";
    tray.notification_text = "Click here to complete the pairing process";
    tray.notification_icon = TRAY_ICON_LOCKED;
    tray.tooltip = PROJECT_NAME;
    tray.notification_cb = []() {
      launch_ui("/clients");
    };
    tray_update(&tray);
  }

  void update_tray_vigem_missing() {
    if (!tray_initialized) {
      return;
    }

    tray.notification_title = nullptr;
    tray.notification_text = nullptr;
    tray.notification_cb = nullptr;
    tray.notification_icon = nullptr;
    tray.icon = TRAY_ICON;
    tray_update(&tray);

    tray.icon = TRAY_ICON;
    tray.notification_title = "Gamepad Input Unavailable";
    tray.notification_text = "ViGEm is not installed. Click for setup info";
    tray.notification_icon = TRAY_ICON;
    tray.tooltip = PROJECT_NAME;
    tray.notification_cb = []() {
      // Open Dashboard for more information
      launch_ui("/");
    };
    tray_update(&tray);
  }

  void tray_notify(const char *title, const char *text, void (*cb)()) {
    if (!tray_initialized) {
      return;
    }

    tray.notification_title = nullptr;
    tray.notification_text = nullptr;
    tray.notification_cb = nullptr;
    tray.notification_icon = nullptr;
    tray.icon = TRAY_ICON;
    tray_update(&tray);

    tray.icon = TRAY_ICON;
    tray.notification_title = title;
    s_notification_text = text ? std::string {text} : std::string {};
    tray.notification_text = s_notification_text.c_str();
    tray.notification_icon = TRAY_ICON;
    tray.tooltip = PROJECT_NAME;
    tray.notification_cb = cb;
    tray_update(&tray);
  }

}  // namespace system_tray
#endif
#endif
