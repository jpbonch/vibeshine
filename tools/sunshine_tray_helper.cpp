/**
 * @file tools/sunshine_tray_helper.cpp
 * @brief Windows tray helper process for Sunshine.
 */

#ifdef _WIN32

  // standard
  #include <atomic>
  #include <array>
  #include <chrono>
  #include <condition_variable>
  #include <cstdint>
  #include <cstring>
  #include <deque>
  #include <filesystem>
  #include <mutex>
  #include <optional>
  #include <span>
  #include <string>
  #include <string_view>
  #include <thread>
  #include <vector>

  // local
  #include "src/logging.h"
  #include "src/platform/windows/ipc/misc_utils.h"
  #include "src/platform/windows/ipc/pipes.h"
  #include "src/platform/windows/ipc/tray_protocol.h"
  #include "src/utility.h"

  // tray
  #include "third-party/tray/src/tray.h"

  // platform
  #define WIN32_LEAN_AND_MEAN
  #include <KnownFolders.h>
  #include <ShlObj.h>
  #include <Windows.h>
  #include <shobjidl.h>
  #include <shellapi.h>

using namespace std::chrono_literals;

#ifndef SUNSHINE_ASSETS_DIR
  #define SUNSHINE_ASSETS_DIR "assets"
#endif

#ifndef PROJECT_NAME
  #define PROJECT_NAME "Sunshine"
#endif

#define WEB_DIR SUNSHINE_ASSETS_DIR "/web/"
#define TRAY_ICON WEB_DIR "images/sunshine.ico"
#define TRAY_ICON_PLAYING WEB_DIR "images/sunshine-playing.ico"
#define TRAY_ICON_PAUSING WEB_DIR "images/sunshine-pausing.ico"
#define TRAY_ICON_LOCKED WEB_DIR "images/sunshine-locked.ico"

namespace {
  using namespace platf::tray_ipc;

  std::atomic<bool> g_running {true};
  std::atomic<bool> g_tray_initialized {false};

  std::mutex g_notification_mutex;
  TrayAction g_notification_action = TrayAction::None;
  std::string g_notification_path;

  std::string g_tooltip;
  std::string g_notification_text;
  std::array<std::string, 4> g_icon_paths;

  enum class IconIndex : std::size_t {
    Default = 0,
    Locked = 1,
    Playing = 2,
    Pausing = 3
  };

  const char *icon_at(IconIndex index) {
    const auto idx = static_cast<std::size_t>(index);
    if (idx < g_icon_paths.size() && !g_icon_paths[idx].empty()) {
      return g_icon_paths[idx].c_str();
    }
    return nullptr;
  }

  const char *icon_default() {
    return icon_at(IconIndex::Default) ? icon_at(IconIndex::Default) : TRAY_ICON;
  }

  const char *icon_locked() {
    return icon_at(IconIndex::Locked) ? icon_at(IconIndex::Locked) : TRAY_ICON_LOCKED;
  }

  const char *icon_playing() {
    return icon_at(IconIndex::Playing) ? icon_at(IconIndex::Playing) : TRAY_ICON_PLAYING;
  }

  const char *icon_pausing() {
    return icon_at(IconIndex::Pausing) ? icon_at(IconIndex::Pausing) : TRAY_ICON_PAUSING;
  }

  void handle_message(std::span<const uint8_t> message);
  std::unique_ptr<platf::dxgi::INamedPipe> create_client_pipe(std::string_view pipe_name);

  void tray_log_bridge(enum tray_log_level level, const char *message) {
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

  class TrayIpcClient {
  public:
    void start() {
      running_.store(true, std::memory_order_release);
      worker_ = std::jthread([this](std::stop_token stop_token) {
        run(stop_token);
      });
    }

    void stop() {
      running_.store(false, std::memory_order_release);
      queue_cv_.notify_all();
      if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
      }
      if (pipe_) {
        pipe_->disconnect();
      }
    }

    void enqueue_action(TrayAction action, std::string_view path = {}) {
      std::vector<uint8_t> payload(1 + path.size());
      payload[0] = static_cast<uint8_t>(action);
      if (!path.empty()) {
        std::memcpy(payload.data() + 1, path.data(), path.size());
      }
      enqueue_message(MsgType::Action, payload);
    }

    void enqueue_message(MsgType type, const std::vector<uint8_t> &payload) {
      std::vector<uint8_t> message(1 + payload.size());
      message[0] = static_cast<uint8_t>(type);
      if (!payload.empty()) {
        std::memcpy(message.data() + 1, payload.data(), payload.size());
      }

      {
        std::lock_guard<std::mutex> lg(queue_mutex_);
        queue_.emplace_back(std::move(message));
      }
      queue_cv_.notify_one();
    }

  private:
    void run(std::stop_token stop_token) {
      while (!stop_token.stop_requested() && running_.load(std::memory_order_acquire)) {
        if (!ensure_connected()) {
          std::this_thread::sleep_for(500ms);
          continue;
        }

        flush_outgoing();
        receive_incoming();
      }
    }

    bool ensure_connected() {
      if (pipe_ && pipe_->is_connected()) {
        return true;
      }

      pipe_.reset();
      pipe_ = create_pipe();
      if (!pipe_) {
        return false;
      }
      return pipe_->is_connected();
    }

    std::unique_ptr<platf::dxgi::INamedPipe> create_pipe() {
      return create_client_pipe(kPipeName);
    }

    void flush_outgoing() {
      std::vector<uint8_t> next;
      {
        std::unique_lock<std::mutex> lk(queue_mutex_);
        if (queue_.empty()) {
          queue_cv_.wait_for(lk, 150ms);
        }
        if (!queue_.empty()) {
          next = std::move(queue_.front());
          queue_.pop_front();
        }
      }

      if (next.empty() || !pipe_) {
        return;
      }

      if (!pipe_->send(next, 5000)) {
        pipe_.reset();
      }
    }

    void receive_incoming() {
      if (!pipe_) {
        return;
      }

      std::array<uint8_t, 65536> buffer {};
      size_t bytes_read = 0;
      const auto result = pipe_->receive(buffer, bytes_read, 150);
      if (result == platf::dxgi::PipeResult::Timeout) {
        return;
      }
      if (result == platf::dxgi::PipeResult::BrokenPipe ||
          result == platf::dxgi::PipeResult::Disconnected ||
          result == platf::dxgi::PipeResult::Error) {
        pipe_.reset();
        return;
      }
      if (result != platf::dxgi::PipeResult::Success || bytes_read == 0) {
        return;
      }

      std::span<const uint8_t> message(buffer.data(), bytes_read);
      handle_message(message);
    }

    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<std::vector<uint8_t>> queue_;
    std::unique_ptr<platf::dxgi::INamedPipe> pipe_;
    std::atomic<bool> running_ {false};
    std::jthread worker_;
  };

  TrayIpcClient &ipc_client() {
    static TrayIpcClient client;
    return client;
  }

  void enqueue_notification_action(TrayAction action, std::string_view path = {}) {
    std::lock_guard<std::mutex> lg(g_notification_mutex);
    g_notification_action = action;
    g_notification_path = std::string(path);
  }

  void notification_clicked() {
    TrayAction action = TrayAction::None;
    std::string path;
    {
      std::lock_guard<std::mutex> lg(g_notification_mutex);
      action = g_notification_action;
      path = g_notification_path;
    }
    if (action == TrayAction::None) {
      return;
    }

    ipc_client().enqueue_action(action, path);
  }

  std::unique_ptr<platf::dxgi::INamedPipe> create_client_pipe(std::string_view pipe_name) {
    std::string pipe_name_str(pipe_name);
    platf::dxgi::FramedPipeFactory anon_factory(std::make_unique<platf::dxgi::AnonymousPipeFactory>());
    auto pipe = anon_factory.create_client(pipe_name_str);
    if (pipe) {
      return pipe;
    }
    platf::dxgi::FramedPipeFactory fallback_factory(std::make_unique<platf::dxgi::NamedPipeFactory>());
    return fallback_factory.create_client(pipe_name_str);
  }

  bool send_action_once(TrayAction action) {
    auto pipe = create_client_pipe(kActionPipeName);
    if (!pipe) {
      return false;
    }
    const std::array<uint8_t, 2> message{
      static_cast<uint8_t>(MsgType::Action),
      static_cast<uint8_t>(action)
    };
    return pipe->send(message, 5000);
  }

  bool is_process_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
      return false;
    }
    auto close_token = util::fail_guard([&]() {
      CloseHandle(token);
    });

    TOKEN_ELEVATION elevation {};
    DWORD size = 0;
    if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
      return false;
    }
    return elevation.TokenIsElevated != 0;
  }

  std::wstring module_path_w() {
    wchar_t module_path[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, module_path, _countof(module_path))) {
      return {};
    }
    return std::wstring(module_path);
  }

  std::optional<std::wstring> build_elevated_args(TrayAction action) {
    switch (action) {
      case TrayAction::Restart:
        return std::wstring(L"--elevated-action=restart");
      case TrayAction::Quit:
        return std::wstring(L"--elevated-action=quit");
      default:
        return std::nullopt;
    }
  }

  bool launch_elevated_self(TrayAction action) {
    auto args = build_elevated_args(action);
    if (!args) {
      return false;
    }
    auto exe = module_path_w();
    if (exe.empty()) {
      return false;
    }

    SHELLEXECUTEINFOW sei {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"runas";
    sei.lpFile = exe.c_str();
    sei.lpParameters = args->c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) {
      return false;
    }
    if (sei.hProcess) {
      CloseHandle(sei.hProcess);
    }
    return true;
  }

  void request_elevated_action(TrayAction action) {
    if (is_process_elevated()) {
      ipc_client().enqueue_action(action);
      return;
    }

    if (!launch_elevated_self(action)) {
      BOOST_LOG(warning) << "Tray helper: elevation request failed or canceled";
    }
  }

  std::optional<TrayAction> parse_elevated_action(int argc, char *argv[]) {
    for (int i = 1; i < argc; ++i) {
      if (!argv[i]) {
        continue;
      }
      std::string arg = argv[i];
      constexpr std::string_view prefix = "--elevated-action=";
      if (arg.rfind(prefix, 0) == 0) {
        const std::string value = arg.substr(prefix.size());
        if (value == "restart") {
          return TrayAction::Restart;
        }
        if (value == "quit") {
          return TrayAction::Quit;
        }
      }
      if (arg == "--elevated-action" && i + 1 < argc && argv[i + 1]) {
        const std::string value = argv[++i];
        if (value == "restart") {
          return TrayAction::Restart;
        }
        if (value == "quit") {
          return TrayAction::Quit;
        }
      }
    }
    return std::nullopt;
  }

  void tray_open_ui_cb([[maybe_unused]] struct tray_menu *item) {
    ipc_client().enqueue_action(TrayAction::OpenUi);
  }

  void tray_check_update_cb([[maybe_unused]] struct tray_menu *item) {
    ipc_client().enqueue_action(TrayAction::CheckUpdate);
  }

  void tray_restart_cb([[maybe_unused]] struct tray_menu *item) {
    request_elevated_action(TrayAction::Restart);
  }

  void tray_quit_cb([[maybe_unused]] struct tray_menu *item) {
    request_elevated_action(TrayAction::Quit);
  }

  struct tray_menu g_tray_menu[] = {
    {.text = "Open Sunshine", .cb = tray_open_ui_cb},
    {.text = "-"},
    {.text = "Check for Update", .cb = tray_check_update_cb},
    {.text = "Restart", .cb = tray_restart_cb},
    {.text = "Quit", .cb = tray_quit_cb},
    {.text = nullptr}
  };

  constexpr size_t kTrayIconCount = 4;

  struct TrayStorage {
    std::unique_ptr<uint8_t[]> buffer;
    tray *tray = nullptr;
  };

  TrayStorage &tray_storage() {
    static TrayStorage storage;
    return storage;
  }

  tray &tray_state() {
    auto &storage = tray_storage();
    if (storage.tray) {
      return *storage.tray;
    }

    const size_t total_bytes = sizeof(tray) + sizeof(const char *) * kTrayIconCount;
    storage.buffer = std::make_unique<uint8_t[]>(total_bytes);
    std::memset(storage.buffer.get(), 0, total_bytes);
    storage.tray = new (storage.buffer.get()) tray{
      .icon = TRAY_ICON,
      .tooltip = PROJECT_NAME,
      .menu = g_tray_menu,
      .iconPathCount = static_cast<int>(kTrayIconCount),
    };

    storage.tray->allIconPaths[0] = TRAY_ICON;
    storage.tray->allIconPaths[1] = TRAY_ICON_LOCKED;
    storage.tray->allIconPaths[2] = TRAY_ICON_PLAYING;
    storage.tray->allIconPaths[3] = TRAY_ICON_PAUSING;
    return *storage.tray;
  }

  void reset_notification_fields() {
    auto &tray = tray_state();
    tray.notification_title = nullptr;
    tray.notification_text = nullptr;
    tray.notification_cb = nullptr;
    tray.notification_icon = nullptr;
  }

  void apply_stream_state(StreamState state, std::string_view app_name, bool notify) {
    if (!g_tray_initialized.load(std::memory_order_acquire)) {
      return;
    }

    reset_notification_fields();
    auto &tray = tray_state();
    tray.icon = (state == StreamState::Playing) ? icon_playing()
           : (state == StreamState::Pausing) ? icon_pausing()
           : icon_default();
    tray_update(&tray);

    if (!notify) {
      if (state == StreamState::Playing) {
        g_tooltip = "Streaming started for " + std::string(app_name);
        tray.tooltip = g_tooltip.c_str();
      } else if (state == StreamState::Pausing) {
        g_tooltip = "Streaming paused for " + std::string(app_name);
        tray.tooltip = g_tooltip.c_str();
      } else {
        tray.tooltip = PROJECT_NAME;
      }
      tray_update(&tray);
      return;
    }

    if (state == StreamState::Playing) {
      g_notification_text = "Streaming started for " + std::string(app_name);
      g_tooltip = g_notification_text;
      tray.notification_title = "Stream Started";
      tray.notification_text = g_notification_text.c_str();
      tray.notification_icon = icon_playing();
      tray.tooltip = g_tooltip.c_str();
      tray.icon = icon_playing();
      tray_update(&tray);
    } else if (state == StreamState::Pausing) {
      g_notification_text = "Streaming paused for " + std::string(app_name);
      g_tooltip = g_notification_text;
      tray.notification_title = "Stream Paused";
      tray.notification_text = g_notification_text.c_str();
      tray.notification_icon = icon_pausing();
      tray.tooltip = g_tooltip.c_str();
      tray.icon = icon_pausing();
      tray_update(&tray);
    } else if (state == StreamState::Stopped) {
      g_notification_text = "Application " + std::string(app_name) + " successfully stopped";
      tray.notification_title = "Application Stopped";
      tray.notification_text = g_notification_text.c_str();
      tray.notification_icon = icon_default();
      tray.tooltip = PROJECT_NAME;
      tray.icon = icon_default();
      tray_update(&tray);
    } else {
      tray.tooltip = PROJECT_NAME;
      tray.icon = icon_default();
      tray_update(&tray);
    }
  }

  void show_pin_notification() {
    if (!g_tray_initialized.load(std::memory_order_acquire)) {
      return;
    }

    reset_notification_fields();
    auto &tray = tray_state();
    tray.icon = icon_default();
    tray_update(&tray);

    enqueue_notification_action(TrayAction::OpenUi, "/clients");
    tray.notification_title = "Incoming Pairing Request";
    tray.notification_text = "Click here to complete the pairing process";
    tray.notification_icon = icon_locked();
    tray.tooltip = PROJECT_NAME;
    tray.notification_cb = notification_clicked;
    tray.icon = icon_default();
    tray_update(&tray);
  }

  void show_vigem_notification() {
    if (!g_tray_initialized.load(std::memory_order_acquire)) {
      return;
    }

    reset_notification_fields();
    auto &tray = tray_state();
    tray.icon = icon_default();
    tray_update(&tray);

    enqueue_notification_action(TrayAction::OpenUi, "/");
    tray.notification_title = "Gamepad Input Unavailable";
    tray.notification_text = "ViGEm is not installed. Click for setup info";
    tray.notification_icon = icon_default();
    tray.tooltip = PROJECT_NAME;
    tray.notification_cb = notification_clicked;
    tray.icon = icon_default();
    tray_update(&tray);
  }

  void show_generic_notification(const std::string &title, const std::string &text, TrayAction action) {
    if (!g_tray_initialized.load(std::memory_order_acquire)) {
      return;
    }

    reset_notification_fields();
    auto &tray = tray_state();
    tray.icon = icon_default();
    tray_update(&tray);

    g_notification_text = text;
    enqueue_notification_action(action);
    tray.notification_title = title.c_str();
    tray.notification_text = g_notification_text.c_str();
    tray.notification_icon = icon_default();
    tray.tooltip = PROJECT_NAME;
    tray.notification_cb = (action == TrayAction::None) ? nullptr : notification_clicked;
    tray.icon = icon_default();
    tray_update(&tray);
  }

  void handle_message(std::span<const uint8_t> message) {
    if (message.empty()) {
      return;
    }
    const auto type = static_cast<MsgType>(message[0]);
    std::span<const uint8_t> payload = message.subspan(1);

    if (type == MsgType::StreamState) {
      if (payload.size() < 2) {
        return;
      }
      auto state = static_cast<StreamState>(payload[0]);
      const bool notify = payload[1] != 0;
      payload = payload.subspan(2);
      std::string app_name;
      if (!payload.empty()) {
        app_name.assign(reinterpret_cast<const char *>(payload.data()), payload.size());
      }
      apply_stream_state(state, app_name, notify);
    } else if (type == MsgType::NotifyPin) {
      show_pin_notification();
    } else if (type == MsgType::NotifyVigem) {
      show_vigem_notification();
    } else if (type == MsgType::NotifyGeneric) {
      if (payload.empty()) {
        return;
      }
      auto action = static_cast<TrayAction>(payload[0]);
      payload = payload.subspan(1);
      std::string title;
      std::string text;
      if (!payload.empty()) {
        const auto *raw = reinterpret_cast<const char *>(payload.data());
        const auto *end = raw + payload.size();
        const auto *nul = static_cast<const char *>(std::memchr(raw, '\0', payload.size()));
        if (nul) {
          title.assign(raw, nul);
          ++nul;
          if (nul <= end) {
            text.assign(nul, end);
          }
        } else {
          title.assign(raw, end);
        }
      }
      show_generic_notification(title, text, action);
    } else if (type == MsgType::Shutdown) {
      g_running.store(false, std::memory_order_release);
      tray_exit();
    } else if (type == MsgType::Ping) {
      ipc_client().enqueue_message(MsgType::Pong, {});
    }
  }

  bool ensure_single_instance(winrt::handle &mutex_out) {
    constexpr wchar_t kMutexName[] = L"Global\\SunshineTrayHelper";
    HANDLE mutex = CreateMutexW(nullptr, TRUE, kMutexName);
    if (!mutex) {
      return false;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
      CloseHandle(mutex);
      return false;
    }
    mutex_out = winrt::handle {mutex};
    return true;
  }

  std::filesystem::path install_root() {
    wchar_t module_path[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, module_path, _countof(module_path))) {
      return {};
    }
    std::filesystem::path exe_path(module_path);
    return exe_path.parent_path().parent_path();
  }

  void set_working_directory() {
    auto root = install_root();
    if (!root.empty()) {
      SetCurrentDirectoryW(root.c_str());
    }
  }

  void set_icon_paths() {
    auto root = install_root();
    if (root.empty()) {
      return;
    }

    const std::array<std::filesystem::path, 5> candidates = {
      root / SUNSHINE_ASSETS_DIR / "web" / "images",
      root / "assets" / "web" / "images",
      root / "build" / "assets" / "web" / "images",
      root / "web" / "images",
      root / "assets" / "web"
    };

    std::filesystem::path images_dir;
    for (const auto &candidate : candidates) {
      std::error_code ec;
      if (std::filesystem::exists(candidate / "sunshine.ico", ec) && !ec) {
        images_dir = candidate;
        break;
      }
    }
    if (images_dir.empty()) {
      return;
    }

    g_icon_paths[static_cast<std::size_t>(IconIndex::Default)] = (images_dir / "sunshine.ico").string();
    g_icon_paths[static_cast<std::size_t>(IconIndex::Locked)] = (images_dir / "sunshine-locked.ico").string();
    g_icon_paths[static_cast<std::size_t>(IconIndex::Playing)] = (images_dir / "sunshine-playing.ico").string();
    g_icon_paths[static_cast<std::size_t>(IconIndex::Pausing)] = (images_dir / "sunshine-pausing.ico").string();

    auto &tray = tray_state();
    tray.allIconPaths[0] = g_icon_paths[static_cast<std::size_t>(IconIndex::Default)].c_str();
    tray.allIconPaths[1] = g_icon_paths[static_cast<std::size_t>(IconIndex::Locked)].c_str();
    tray.allIconPaths[2] = g_icon_paths[static_cast<std::size_t>(IconIndex::Playing)].c_str();
    tray.allIconPaths[3] = g_icon_paths[static_cast<std::size_t>(IconIndex::Pausing)].c_str();
    tray.icon = tray.allIconPaths[0];
  }

  std::filesystem::path compute_log_dir() {
    std::filesystem::path base;
    platf::dxgi::safe_token user_token;
    user_token.reset(platf::dxgi::retrieve_users_token(false));

    auto try_known_folder = [&](REFKNOWNFOLDERID id) {
      PWSTR path_w = nullptr;
      if (SUCCEEDED(SHGetKnownFolderPath(id, 0, user_token.get(), &path_w)) && path_w) {
        base = std::filesystem::path(path_w) / L"Sunshine";
        CoTaskMemFree(path_w);
        return true;
      }
      return false;
    };

    if (!try_known_folder(FOLDERID_RoamingAppData)) {
      try_known_folder(FOLDERID_LocalAppData);
    }

    if (base.empty()) {
      std::error_code ec;
      base = std::filesystem::current_path(ec) / L"Sunshine";
    }

    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    return base;
  }

  bool prepare_desktop_for_tray() {
    // Wait for the shell to be initialized before registering the tray icon.
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
      BOOST_LOG(warning) << "Timed out waiting for interactive desktop; system tray may not appear";
      return false;
    }

    BOOST_LOG(debug) << "Interactive desktop ready for tray initialization";
    return true;
  }

  bool init_tray() {
    tray_set_log_callback(&tray_log_bridge);
    prepare_desktop_for_tray();
    set_icon_paths();

    int attempt = 0;
    int tray_init_result = -1;
    while (tray_init_result < 0 && attempt < 30) {
      tray_init_result = tray_init(&tray_state());
      if (tray_init_result >= 0) {
        break;
      }
      auto last_error = GetLastError();
      BOOST_LOG(warning) << "Failed to create system tray (attempt " << attempt + 1 << ", error " << last_error << ')';
      std::this_thread::sleep_for(2s);
      ++attempt;
    }

    if (tray_init_result < 0) {
      BOOST_LOG(warning) << "Failed to create system tray after retries";
      return false;
    }

    BOOST_LOG(info) << "System tray created";
    g_tray_initialized.store(true, std::memory_order_release);
    return true;
  }
}  // namespace

int main(int argc, char *argv[]) {
  set_working_directory();
  SetCurrentProcessExplicitAppUserModelID(L"Vibeshine");

  if (auto elevated_action = parse_elevated_action(argc, argv)) {
    return send_action_once(*elevated_action) ? 0 : 1;
  }

  winrt::handle singleton;
  if (!ensure_single_instance(singleton)) {
    return 3;
  }

  const auto logdir = compute_log_dir();
  const auto logfile = logdir / L"vibeshine_tray.log";
  auto log_guard = logging::init(2 /*info*/, logfile);

  if (!init_tray()) {
    return 1;
  }

  ipc_client().start();

  while (g_running.load(std::memory_order_acquire) && tray_loop(1) == 0) {
    std::this_thread::sleep_for(10ms);
  }

  ipc_client().stop();
  logging::log_flush();
  return 0;
}

#else
int main() {
  return 0;
}
#endif
