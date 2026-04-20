#include <windows.h>
#include <fltuser.h>
#include <algorithm>
#include <iostream>
#include <atomic>
#include <mutex>
#include <nlohmann/json.hpp>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <string>

#include "CommonUtils.h"
#include "DriverUtils.h"
#include "Shared.h"
#include "RuleManager.h"

using json = nlohmann::json;

RuleManager g_RuleManager;
std::wstring g_ExeDirectory;

namespace {
    const wchar_t kHostGuardServiceName[] = L"HostGuard";
    const wchar_t kHostGuardDisplayName[] = L"HostGuard Endpoint Protection";
    const wchar_t kDriverServiceName[] = L"PebMonitor";
    const wchar_t kDriverSelfProtectionRuleId[] = L"driver_self_protection";

    HANDLE g_StopEvent = NULL;
    HANDLE g_ShutdownCompleteEvent = NULL;
    std::atomic<void*> g_MainDeviceHandle{ INVALID_HANDLE_VALUE };
    std::atomic<void*> g_DriverEventDeviceHandle{ INVALID_HANDLE_VALUE };
    std::atomic<void*> g_HeartbeatDeviceHandle{ INVALID_HANDLE_VALUE };
    std::atomic<void*> g_ProcessPortHandle{ INVALID_HANDLE_VALUE };
    SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
    SERVICE_STATUS g_ServiceStatus = {};
    bool g_IsServiceMode = false;

    struct ProcessPortMessageBuffer {
        FILTER_MESSAGE_HEADER header;
        PROCESS_PORT_REQUEST request;
    };

    struct ProcessPortReplyBuffer {
        FILTER_REPLY_HEADER header;
        PROCESS_PORT_REPLY reply;
    };

    ;

    ;

    struct ProcessCacheEntry {
        std::wstring processName;
        std::wstring commandLine;
        std::wstring imagePath;
        ULONGLONG createTime = 0;
        ULONGLONG lastSeenTick = 0;
    };

    struct FileState {
        bool exists = false;
        FILETIME lastWriteTime = {};
        DWORD fileSizeHigh = 0;
        DWORD fileSizeLow = 0;
    };

    std::mutex g_ProcessCacheLock;
    std::unordered_map<DWORD, ProcessCacheEntry> g_ProcessCache;
    const size_t kMaxProcessCacheEntries = 4096;
    const ULONGLONG kProcessCacheTtlMs = 10ULL * 60ULL * 1000ULL;
    std::mutex g_AutoResponseLock;
    std::unordered_map<DWORD, ULONGLONG> g_AutoTerminateHistory;
    const size_t kMaxAutoTerminateHistoryEntries = 2048;
    const ULONGLONG kAutoTerminateHistoryRetentionMs = 10ULL * 60ULL * 1000ULL;
    const LONG kDefaultTerminateExitStatus = static_cast<LONG>(0xC0000022L);

    bool IsTrackedHandleValid(HANDLE handle) {
        return handle != NULL && handle != INVALID_HANDLE_VALUE;
    }

    void TrackDeviceHandle(std::atomic<void*>& slot, HANDLE handle) {
        slot.store(handle, std::memory_order_release);
    }

    void UntrackDeviceHandle(std::atomic<void*>& slot, HANDLE handle) {
        void* expected = handle;
        slot.compare_exchange_strong(
            expected,
            INVALID_HANDLE_VALUE,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
    }

    void CloseTrackedHandle(HANDLE& handle, std::atomic<void*>& slot) {
        if (!IsTrackedHandleValid(handle)) {
            handle = INVALID_HANDLE_VALUE;
            return;
        }

        UntrackDeviceHandle(slot, handle);
        CloseHandle(handle);
        handle = INVALID_HANDLE_VALUE;
    }

    bool IsShutdownRequested() {
        return g_StopEvent != NULL && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0;
    }

    bool WaitForShutdown(DWORD timeoutMs) {
        return g_StopEvent != NULL && WaitForSingleObject(g_StopEvent, timeoutMs) == WAIT_OBJECT_0;
    }

    void RequestShutdown() {
        if (g_StopEvent != NULL) {
            SetEvent(g_StopEvent);
        }

        HANDLE mainDeviceHandle = reinterpret_cast<HANDLE>(g_MainDeviceHandle.load(std::memory_order_acquire));
        if (IsTrackedHandleValid(mainDeviceHandle)) {
            CancelIoEx(mainDeviceHandle, NULL);
        }

        HANDLE driverEventHandle = reinterpret_cast<HANDLE>(g_DriverEventDeviceHandle.load(std::memory_order_acquire));
        if (IsTrackedHandleValid(driverEventHandle) && driverEventHandle != mainDeviceHandle) {
            CancelIoEx(driverEventHandle, NULL);
        }

        HANDLE heartbeatHandle = reinterpret_cast<HANDLE>(g_HeartbeatDeviceHandle.load(std::memory_order_acquire));
        if (IsTrackedHandleValid(heartbeatHandle) &&
            heartbeatHandle != mainDeviceHandle &&
            heartbeatHandle != driverEventHandle) {
            CancelIoEx(heartbeatHandle, NULL);
        }

        HANDLE processPortHandle = reinterpret_cast<HANDLE>(g_ProcessPortHandle.load(std::memory_order_acquire));
        if (IsTrackedHandleValid(processPortHandle) &&
            processPortHandle != mainDeviceHandle &&
            processPortHandle != driverEventHandle &&
            processPortHandle != heartbeatHandle) {
            CancelIoEx(processPortHandle, NULL);
        }

    }

    bool EnsureRuntimeEvents() {
        if (g_StopEvent == NULL) {
            g_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        }
        if (g_ShutdownCompleteEvent == NULL) {
            g_ShutdownCompleteEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        }

        if (g_StopEvent == NULL || g_ShutdownCompleteEvent == NULL) {
            return false;
        }

        ResetEvent(g_StopEvent);
        ResetEvent(g_ShutdownCompleteEvent);
        return true;
    }

    void CleanupRuntimeEvents() {
        if (g_StopEvent != NULL) {
            CloseHandle(g_StopEvent);
            g_StopEvent = NULL;
        }
        if (g_ShutdownCompleteEvent != NULL) {
            CloseHandle(g_ShutdownCompleteEvent);
            g_ShutdownCompleteEvent = NULL;
        }
    }

    void ReportServiceStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint) {
        if (g_ServiceStatusHandle == NULL) {
            return;
        }

        g_ServiceStatus.dwCurrentState = currentState;
        g_ServiceStatus.dwWin32ExitCode = win32ExitCode;
        g_ServiceStatus.dwWaitHint = waitHint;
        g_ServiceStatus.dwControlsAccepted =
            (currentState == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
        g_ServiceStatus.dwCheckPoint =
            (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) ? 0 : g_ServiceStatus.dwCheckPoint + 1;

        SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
    }

    DWORD WINAPI ServiceControlHandlerEx(
        DWORD control,
        DWORD eventType,
        LPVOID eventData,
        LPVOID context) {
        UNREFERENCED_PARAMETER(eventType);
        UNREFERENCED_PARAMETER(eventData);
        UNREFERENCED_PARAMETER(context);

        switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 15000);
            RequestShutdown();
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            ReportServiceStatus(g_ServiceStatus.dwCurrentState, NO_ERROR, 0);
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
        }
    }

    BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
        switch (ctrlType) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            RequestShutdown();
            if (g_ShutdownCompleteEvent != NULL) {
                WaitForSingleObject(g_ShutdownCompleteEvent, 15000);
            }
            return TRUE;
        default:
            return FALSE;
        }
    }

    bool QueryFileState(const std::wstring& filePath, FileState& state) {
        WIN32_FILE_ATTRIBUTE_DATA attributes = {};
        if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &attributes)) {
            state = FileState{};
            return false;
        }

        state.exists = true;
        state.lastWriteTime = attributes.ftLastWriteTime;
        state.fileSizeHigh = attributes.nFileSizeHigh;
        state.fileSizeLow = attributes.nFileSizeLow;
        return true;
    }

    bool IsSameFileState(const FileState& left, const FileState& right) {
        return left.exists == right.exists &&
            left.fileSizeHigh == right.fileSizeHigh &&
            left.fileSizeLow == right.fileSizeLow &&
            left.lastWriteTime.dwLowDateTime == right.lastWriteTime.dwLowDateTime &&
            left.lastWriteTime.dwHighDateTime == right.lastWriteTime.dwHighDateTime;
    }

    std::wstring RegistryOperationToString(ULONG operation) {
        switch (operation) {
        case REGISTRY_OPERATION_SET_VALUE:
            return L"set_value";
        case REGISTRY_OPERATION_CREATE_KEY:
            return L"create_key";
        case REGISTRY_OPERATION_DELETE_VALUE:
            return L"delete_value";
        case REGISTRY_OPERATION_DELETE_KEY:
            return L"delete_key";
        case REGISTRY_OPERATION_RENAME_KEY:
            return L"rename_key";
        case REGISTRY_OPERATION_SET_INFORMATION_KEY:
            return L"set_information_key";
        default:
            return L"unknown";
        }
    }

        std::wstring DescribeConfigIdentity(const RuleConfiguration& config) {
        std::wstring description =
            L"Profile=" + (config.profileName.empty() ? L"default" : config.profileName) +
            L", Version=" + (config.configVersion.empty() ? L"unversioned" : config.configVersion);
        if (!config.generatedAt.empty()) {
            description += L", GeneratedAt=" + config.generatedAt;
        }
        if (!config.sourcePath.empty()) {
            description += L", RulesPath=" + config.sourcePath;
        }

        return description;
    }

    std::wstring ProcessVerdictFailModeToString(ULONG failMode) {
        return (failMode == PROCESS_VERDICT_FAIL_CLOSE) ? L"fail_close" : L"fail_open";
    }

    std::wstring ProtectionModeToString(ULONG protectionMode) {
        return (protectionMode == HIPS_MODE_MONITOR_ONLY) ? L"monitor_only" : L"blocking";
    }

    std::wstring ResponseActionToString(ULONG responseAction) {
        switch (responseAction) {
        case RESPONSE_ACTION_TERMINATE_PROCESS:
            return L"terminate_process";
        default:
            return L"unknown_response_action";
        }
    }

    std::wstring DriverEventTypeToString(ULONG eventType) {
        switch (eventType) {
        case DRIVER_EVENT_TYPE_BLOCKED_REGISTRY_OPERATION:
            return L"blocked_registry_operation";
        case DRIVER_EVENT_TYPE_OBSERVED_REGISTRY_OPERATION:
            return L"observed_registry_operation";
        case DRIVER_EVENT_TYPE_OBSERVED_PROCESS_CREATE:
            return L"observed_process_create";
        case DRIVER_EVENT_TYPE_RESPONSE_ACTION:
            return L"response_action";
        case DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION:
            return L"blocked_file_operation";
        default:
            return L"unknown_driver_event";
        }
    }
    std::wstring FormatNtStatusHex(LONG status) {
        wchar_t buffer[32] = {};
        swprintf_s(buffer, RTL_NUMBER_OF(buffer), L"0x%08X", static_cast<unsigned int>(status));
        return std::wstring(buffer);
    }

    bool HasConfigIdentityChanged(const RuleConfiguration& previousConfig, const RuleConfiguration& newConfig) {
        return previousConfig.profileName != newConfig.profileName ||
            previousConfig.configVersion != newConfig.configVersion ||
            previousConfig.generatedAt != newConfig.generatedAt ||
            previousConfig.sourcePath != newConfig.sourcePath;
    }

    void AppendPrefixedConfigFields(
        json& event,
        const RuleConfiguration& config,
        const char* prefix) {
        const std::string keyPrefix = (prefix != nullptr) ? prefix : "";

        if (!config.profileName.empty()) {
            event[keyPrefix + "profile_name"] = WStringToUtf8(config.profileName);
        }
        if (!config.configVersion.empty()) {
            event[keyPrefix + "config_version"] = WStringToUtf8(config.configVersion);
        }
        if (!config.generatedAt.empty()) {
            event[keyPrefix + "generated_at"] = WStringToUtf8(config.generatedAt);
        }
        if (!config.sourcePath.empty()) {
            event[keyPrefix + "rules_path"] = WStringToUtf8(config.sourcePath);
        }
        event[keyPrefix + "process_verdict_timeout_ms"] = config.processVerdictTimeoutMs;
        event[keyPrefix + "process_verdict_fail_mode"] =
            WStringToUtf8(ProcessVerdictFailModeToString(config.processVerdictFailMode));
        event[keyPrefix + "capture_parent_cmdline"] =
            (config.captureParentCommandLine == PROCESS_PARENT_CMDLINE_CAPTURE_ENABLED);
        event[keyPrefix + "auto_terminate_on_registry_block"] =
            config.autoResponse.terminateOnRegistryBlock;
        event[keyPrefix + "auto_terminate_min_severity"] =
            config.autoResponse.minSeverity;
        event[keyPrefix + "auto_terminate_cooldown_ms"] =
            config.autoResponse.cooldownMs;
    }

    void AppendRegistryRuleClassStatsFields(
        json& event,
        const RegistryRuleClassStats& stats,
        const char* prefix) {
        const std::string keyPrefix = (prefix != nullptr) ? prefix : "";
        event[keyPrefix + "total"] = stats.totalRules;
        event[keyPrefix + "exact"] = stats.exactRules;
        event[keyPrefix + "prefix"] = stats.prefixRules;
        event[keyPrefix + "suffix"] = stats.suffixRules;
        event[keyPrefix + "contains"] = stats.containsRules;
    }

    void LogRegistryRuleClassStats(
        const std::wstring& label,
        const RegistryRuleClassStats& stats) {
        LogMessage(
            label +
            L": total=" + std::to_wstring(stats.totalRules) +
            L", exact=" + std::to_wstring(stats.exactRules) +
            L", prefix=" + std::to_wstring(stats.prefixRules) +
            L", suffix=" + std::to_wstring(stats.suffixRules) +
            L", contains=" + std::to_wstring(stats.containsRules));
    }

    void LogConfigSummary(const RuleConfiguration& config) {
        std::wstring prefix = L"[+] 当前配置已生效";
        if (!config.profileName.empty() || !config.configVersion.empty()) {
            prefix += L" (Profile=" +
                (config.profileName.empty() ? L"default" : config.profileName) +
                L", Version=" +
                (config.configVersion.empty() ? L"unversioned" : config.configVersion) +
                L")";
        }
        if (!config.generatedAt.empty()) {
            prefix += L" [GeneratedAt=" + config.generatedAt + L"]";
        }

        LogMessage(
            prefix +
            L": 进程规则 " + std::to_wstring(config.processRules.size()) +
            L" 条, 进程白名单 " + std::to_wstring(config.processAllowRules.size()) +
            L" 条, 注册表规则 " + std::to_wstring(config.registryRuleDefinitions.size()) +
            L" 条, 注册表白名单 " + std::to_wstring(config.registryAllowRuleDefinitions.size()) +
            L" 条, 进程裁决超时 " + std::to_wstring(config.processVerdictTimeoutMs) +
            L"ms, 超时策略 " + ProcessVerdictFailModeToString(config.processVerdictFailMode) +
            L", 父命令行捕获 " +
            std::wstring((config.captureParentCommandLine == PROCESS_PARENT_CMDLINE_CAPTURE_ENABLED) ? L"enabled" : L"disabled") +
             L", 自动终止[registry=" +
             std::wstring(config.autoResponse.terminateOnRegistryBlock ? L"on" : L"off") +
             L", min_severity=" + std::to_wstring(config.autoResponse.minSeverity) +
             L", cooldown=" + std::to_wstring(config.autoResponse.cooldownMs) + L"ms]。"
         );

        LogRegistryRuleClassStats(L"[*] 注册表规则分类[block]", config.registryRuleClassStats);
        LogRegistryRuleClassStats(L"[*] 注册表规则分类[allow]", config.registryAllowRuleClassStats);
    }
    std::wstring FormatDriverSystemTimeValue(ULONGLONG rawTime) {
        if (rawTime == 0) {
            return L"<never>";
        }

        FILETIME fileTime = {};
        fileTime.dwLowDateTime = static_cast<DWORD>(rawTime & 0xFFFFFFFFULL);
        fileTime.dwHighDateTime = static_cast<DWORD>(rawTime >> 32);

        SYSTEMTIME utcTime = {};
        SYSTEMTIME localTime = {};
        if (!FileTimeToSystemTime(&fileTime, &utcTime)) {
            return L"<invalid>";
        }

        if (!SystemTimeToTzSpecificLocalTime(NULL, &utcTime, &localTime)) {
            localTime = utcTime;
        }

        wchar_t buffer[64] = {};
        swprintf_s(
            buffer,
            RTL_NUMBER_OF(buffer),
            L"%04u-%02u-%02u %02u:%02u:%02u",
            localTime.wYear,
            localTime.wMonth,
            localTime.wDay,
            localTime.wHour,
            localTime.wMinute,
            localTime.wSecond);
        return std::wstring(buffer);
    }

    json BuildDriverStatusJson(const DRIVER_RUNTIME_STATUS& status) {
        json driverStatus = json::object();

        driverStatus["abi_version"] = status.AbiVersion;
        driverStatus["status_flags"] = status.StatusFlags;
        driverStatus["device_ready"] = (status.StatusFlags & DRIVER_STATUS_FLAG_DEVICE_READY) != 0;
        driverStatus["process_callback_registered"] =
            (status.StatusFlags & DRIVER_STATUS_FLAG_PROCESS_CALLBACK_REGISTERED) != 0;
        driverStatus["registry_callback_registered"] =
            (status.StatusFlags & DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED) != 0;
        driverStatus["process_port_connected"] =
            (status.StatusFlags & DRIVER_STATUS_FLAG_PROCESS_PORT_CONNECTED) != 0;
        driverStatus["process_breaker_open"] =
            (status.StatusFlags & DRIVER_STATUS_FLAG_PROCESS_BREAKER_OPEN) != 0;
        driverStatus["monitor_only"] = (status.StatusFlags & DRIVER_STATUS_FLAG_MONITOR_ONLY) != 0;
        driverStatus["protection_mode"] = WStringToUtf8(ProtectionModeToString(status.ProtectionMode));
        driverStatus["policy_epoch"] = status.PolicyEpoch;

        driverStatus["registry_rule_count"] = status.RegistryRuleCount;
        driverStatus["registry_allow_rule_count"] = status.RegistryAllowRuleCount;
        json registryRuleClasses = json::object();
        registryRuleClasses["total"] = status.RegistryRuleCount;
        registryRuleClasses["exact"] = status.RegistryRuleExactCount;
        registryRuleClasses["prefix"] = status.RegistryRulePrefixCount;
        registryRuleClasses["suffix"] = status.RegistryRuleSuffixCount;
        registryRuleClasses["contains"] = status.RegistryRuleContainsCount;
        driverStatus["registry_rule_classes"] = registryRuleClasses;

        json registryAllowRuleClasses = json::object();
        registryAllowRuleClasses["total"] = status.RegistryAllowRuleCount;
        registryAllowRuleClasses["exact"] = status.RegistryAllowRuleExactCount;
        registryAllowRuleClasses["prefix"] = status.RegistryAllowRulePrefixCount;
        registryAllowRuleClasses["suffix"] = status.RegistryAllowRuleSuffixCount;
        registryAllowRuleClasses["contains"] = status.RegistryAllowRuleContainsCount;
        driverStatus["registry_allow_rule_classes"] = registryAllowRuleClasses;
        driverStatus["driver_event_queue_count"] = status.DriverEventQueueCount;
        driverStatus["capture_parent_cmdline"] =
            (status.CaptureParentCommandLine == PROCESS_PARENT_CMDLINE_CAPTURE_ENABLED);

        driverStatus["driver_event_drop_count"] = status.DriverEventDropCount;
        driverStatus["driver_event_alloc_fail_count"] = status.DriverEventAllocFailCount;
        driverStatus["process_verdict_request_count"] = status.ProcessVerdictRequestCount;
        driverStatus["process_verdict_timeout_count"] = status.ProcessVerdictTimeoutCount;
        driverStatus["process_port_connect_count"] = status.ProcessPortConnectCount;
        driverStatus["process_port_disconnect_count"] = status.ProcessPortDisconnectCount;
        driverStatus["process_breaker_open_count"] = status.ProcessBreakerOpenCount;

        driverStatus["last_process_port_connect_time"] = status.LastProcessPortConnectTime;
        driverStatus["last_process_port_disconnect_time"] = status.LastProcessPortDisconnectTime;
        driverStatus["last_process_verdict_timeout_time"] = status.LastProcessVerdictTimeoutTime;
        driverStatus["last_heartbeat_time"] = status.LastHeartbeatTime;
        driverStatus["last_process_breaker_open_time"] = status.LastProcessBreakerOpenTime;
        driverStatus["last_process_breaker_close_time"] = status.LastProcessBreakerCloseTime;

        driverStatus["last_process_port_connect_text"] =
            WStringToUtf8(FormatDriverSystemTimeValue(status.LastProcessPortConnectTime));
        driverStatus["last_process_port_disconnect_text"] =
            WStringToUtf8(FormatDriverSystemTimeValue(status.LastProcessPortDisconnectTime));
        driverStatus["last_process_verdict_timeout_text"] =
            WStringToUtf8(FormatDriverSystemTimeValue(status.LastProcessVerdictTimeoutTime));
        driverStatus["last_heartbeat_text"] =
            WStringToUtf8(FormatDriverSystemTimeValue(status.LastHeartbeatTime));
        driverStatus["last_process_breaker_open_text"] =
            WStringToUtf8(FormatDriverSystemTimeValue(status.LastProcessBreakerOpenTime));
        driverStatus["last_process_breaker_close_text"] =
            WStringToUtf8(FormatDriverSystemTimeValue(status.LastProcessBreakerCloseTime));

        driverStatus["process_verdict_timeout_ms"] = status.ProcessVerdictTimeoutMs;
        driverStatus["process_verdict_fail_mode"] =
            WStringToUtf8(ProcessVerdictFailModeToString(status.ProcessVerdictFailMode));
        driverStatus["heartbeat_interval_ms"] = status.HeartbeatIntervalMs;
        driverStatus["heartbeat_timeout_ms"] = status.HeartbeatTimeoutMs;

        driverStatus["fast_path_hit_count"] = status.FastPathHitCount;
        driverStatus["cache_hit_count"] = status.CacheHitCount;
        driverStatus["cache_miss_count"] = status.CacheMissCount;
        driverStatus["cache_flush_count"] = status.CacheFlushCount;
        driverStatus["slow_path_count"] = status.SlowPathCount;
        driverStatus["file_protection_block_count"] = status.FileProtectionBlockCount;
        driverStatus["file_protection_create_block_count"] = status.FileProtectionCreateBlockCount;
        driverStatus["file_protection_set_information_block_count"] = status.FileProtectionSetInformationBlockCount;
        driverStatus["last_file_protection_info_class"] = WStringToUtf8(status.LastFileProtectionInfoClass);

        if (status.ConfigVersion[0] != L'\0') {
            driverStatus["config_version"] = WStringToUtf8(status.ConfigVersion);
        }
        if (status.ProfileName[0] != L'\0') {
            driverStatus["profile_name"] = WStringToUtf8(status.ProfileName);
        }
        if (status.GeneratedAt[0] != L'\0') {
            driverStatus["generated_at"] = WStringToUtf8(status.GeneratedAt);
        }

        return driverStatus;
    }

    void LogDriverStatusSnapshot(const DRIVER_RUNTIME_STATUS& status) {
        std::wstring flagsText;
        if (status.StatusFlags & DRIVER_STATUS_FLAG_DEVICE_READY) {
            flagsText += L"device ";
        }
        if (status.StatusFlags & DRIVER_STATUS_FLAG_PROCESS_CALLBACK_REGISTERED) {
            flagsText += L"process_cb ";
        }
        if (status.StatusFlags & DRIVER_STATUS_FLAG_REGISTRY_CALLBACK_REGISTERED) {
            flagsText += L"registry_cb ";
        }
        if (status.StatusFlags & DRIVER_STATUS_FLAG_PROCESS_PORT_CONNECTED) {
            flagsText += L"process_port ";
        }
        if (status.StatusFlags & DRIVER_STATUS_FLAG_PROCESS_BREAKER_OPEN) {
            flagsText += L"process_breaker ";
        }
        if (status.StatusFlags & DRIVER_STATUS_FLAG_MONITOR_ONLY) {
            flagsText += L"monitor_only ";
        }
        if (flagsText.empty()) {
            flagsText = L"<none>";
        }

        LogMessage(
            L"[+] 驱动状态: Flags=" + flagsText +
            L", protection_mode=" + ProtectionModeToString(status.ProtectionMode) +
            L", 注册表拦截规则=" + std::to_wstring(status.RegistryRuleCount) +
            L", 注册表白名单规则=" + std::to_wstring(status.RegistryAllowRuleCount) +
            L", 驱动事件队列=" + std::to_wstring(status.DriverEventQueueCount) +
            L", 事件丢弃=" + std::to_wstring(status.DriverEventDropCount) +
            L", 分配失败=" + std::to_wstring(status.DriverEventAllocFailCount));

        LogMessage(
            L"[+] 文件保护状态: 阻断总数=" + std::to_wstring(status.FileProtectionBlockCount) +
            L", create阻断=" + std::to_wstring(status.FileProtectionCreateBlockCount) +
            L", setinfo阻断=" + std::to_wstring(status.FileProtectionSetInformationBlockCount) +
            L", 最近类型=" +
            std::wstring(status.LastFileProtectionInfoClass[0] != L'\0' ? status.LastFileProtectionInfoClass : L"<none>"));

        LogMessage(
            L"[+] 进程裁决链路: connected=" +
            std::wstring((status.StatusFlags & DRIVER_STATUS_FLAG_PROCESS_PORT_CONNECTED) ? L"yes" : L"no") +
            L", breaker_open=" +
            std::wstring((status.StatusFlags & DRIVER_STATUS_FLAG_PROCESS_BREAKER_OPEN) ? L"yes" : L"no") +
            L", 请求=" + std::to_wstring(status.ProcessVerdictRequestCount) +
            L", 超时=" + std::to_wstring(status.ProcessVerdictTimeoutCount) +
            L", 端口连接=" + std::to_wstring(status.ProcessPortConnectCount) +
            L", 端口断开=" + std::to_wstring(status.ProcessPortDisconnectCount));

        LogMessage(
            L"[+] 进程裁决策略: timeout=" + std::to_wstring(status.ProcessVerdictTimeoutMs) +
            L"ms, fail_mode=" + ProcessVerdictFailModeToString(status.ProcessVerdictFailMode) +
            L", heartbeat_interval=" + std::to_wstring(status.HeartbeatIntervalMs) +
            L"ms, heartbeat_timeout=" + std::to_wstring(status.HeartbeatTimeoutMs) + L"ms" +
            L", capture_parent_cmdline=" +
            std::wstring((status.CaptureParentCommandLine == PROCESS_PARENT_CMDLINE_CAPTURE_ENABLED) ? L"enabled" : L"disabled"));

        LogMessage(
            L"[+] 进程裁决时间点: 最近连接=" + FormatDriverSystemTimeValue(status.LastProcessPortConnectTime) +
            L", 最近断开=" + FormatDriverSystemTimeValue(status.LastProcessPortDisconnectTime) +
            L", 最近超时=" + FormatDriverSystemTimeValue(status.LastProcessVerdictTimeoutTime) +
            L", 最近心跳=" + FormatDriverSystemTimeValue(status.LastHeartbeatTime));

        LogMessage(
            L"[+] 进程断路器状态: 打开次数=" + std::to_wstring(status.ProcessBreakerOpenCount) +
            L", 最近打开=" + FormatDriverSystemTimeValue(status.LastProcessBreakerOpenTime) +
            L", 最近关闭=" + FormatDriverSystemTimeValue(status.LastProcessBreakerCloseTime));

        if (status.ConfigVersion[0] != L'\0' || status.ProfileName[0] != L'\0') {
            LogMessage(
                L"[+] 驱动当前配置: Profile=" + std::wstring(status.ProfileName) +
                L", Version=" + std::wstring(status.ConfigVersion) +
                (status.GeneratedAt[0] != L'\0' ? (L", GeneratedAt=" + std::wstring(status.GeneratedAt)) : L""));
        }
    }
    bool QueryAndLogDriverStatus(HANDLE hDevice) {
        DRIVER_RUNTIME_STATUS status = {};
        if (!QueryDriverStatus(hDevice, status)) {
            LogMessage(L"[!] 警告：查询驱动状态失败，无法确认内核规则同步是否完成。");
            return false;
        }

        LogDriverStatusSnapshot(status);
        return true;
    }

    json BuildBaseJsonEvent(
        const char* eventType,
        const char* level,
        const RuleConfiguration& config) {
        json event;
        PopulateCommonJsonEventFields(event, eventType, level);
        PopulateRuleContextJsonFields(event, config.profileName, config.configVersion, config.generatedAt);
        if (!config.sourcePath.empty()) {
            event["rules_path"] = WStringToUtf8(config.sourcePath);
        }
        return event;
    }

    json BuildBaseJsonEvent(const char* eventType, const char* level) {
        return BuildBaseJsonEvent(eventType, level, g_RuleManager.GetRuleConfigurationSnapshot());
    }

    void EmitJsonEvent(const json& event) {
        AppendJsonLogLine(event.dump(-1, ' ', true));
    }

    std::wstring ToLowerCopy(const std::wstring& value) {
        std::wstring lowered = value;
        std::transform(
            lowered.begin(),
            lowered.end(),
            lowered.begin(),
            [](wchar_t ch) { return static_cast<wchar_t>(towlower(static_cast<wint_t>(ch))); });
        return lowered;
    }

    std::wstring ExtractProcessNameFromImagePath(const std::wstring& imagePath) {
        if (imagePath.empty()) {
            return L"";
        }

        size_t offset = imagePath.find_last_of(L"\\/");
        std::wstring fileName =
            (offset == std::wstring::npos) ? imagePath : imagePath.substr(offset + 1);
        return ToLowerCopy(fileName);
    }

    void PruneProcessCacheLocked(ULONGLONG nowTick) {
        for (std::unordered_map<DWORD, ProcessCacheEntry>::iterator it = g_ProcessCache.begin();
            it != g_ProcessCache.end();) {
            if (nowTick - it->second.lastSeenTick > kProcessCacheTtlMs) {
                it = g_ProcessCache.erase(it);
            }
            else {
                ++it;
            }
        }

        while (g_ProcessCache.size() > kMaxProcessCacheEntries) {
            std::unordered_map<DWORD, ProcessCacheEntry>::iterator oldestIt = g_ProcessCache.begin();
            for (std::unordered_map<DWORD, ProcessCacheEntry>::iterator it = g_ProcessCache.begin();
                it != g_ProcessCache.end();
                ++it) {
                if (it->second.lastSeenTick < oldestIt->second.lastSeenTick) {
                    oldestIt = it;
                }
            }
            g_ProcessCache.erase(oldestIt);
        }
    }

    void CacheProcessContext(
        DWORD pid,
        const std::wstring& processName,
        const std::wstring& commandLine,
        const std::wstring& imagePath = L"") {
        if (pid == 0 || (processName.empty() && commandLine.empty() && imagePath.empty())) {
            return;
        }

        const ULONGLONG nowTick = GetTickCount64();
        std::lock_guard<std::mutex> lock(g_ProcessCacheLock);
        ProcessCacheEntry& entry = g_ProcessCache[pid];
        if (!processName.empty() && processName != L"<unknown>") {
            entry.processName = processName;
        }
        if (!commandLine.empty()) {
            entry.commandLine = commandLine;
        }
        if (!imagePath.empty()) {
            entry.imagePath = imagePath;
        }
        if (entry.createTime == 0) {
            entry.createTime = nowTick;
        }
        entry.lastSeenTick = nowTick;
        PruneProcessCacheLocked(entry.lastSeenTick);
    }

    std::wstring GetCachedProcessName(DWORD pid) {
        if (pid == 0) {
            return L"";
        }

        std::lock_guard<std::mutex> lock(g_ProcessCacheLock);
        std::unordered_map<DWORD, ProcessCacheEntry>::const_iterator it = g_ProcessCache.find(pid);
        if (it == g_ProcessCache.end()) {
            return L"";
        }
        return it->second.processName;
    }

    std::wstring GetCachedProcessCommandLine(DWORD pid) {
        if (pid == 0) {
            return L"";
        }

        std::lock_guard<std::mutex> lock(g_ProcessCacheLock);
        std::unordered_map<DWORD, ProcessCacheEntry>::const_iterator it = g_ProcessCache.find(pid);
        if (it == g_ProcessCache.end()) {
            return L"";
        }
        return it->second.commandLine;
    }
}

static std::wstring FindLocalDriverPath() {
    const std::wstring candidates[] = {
        g_ExeDirectory + L"PebMonitor.sys",
        g_ExeDirectory + L"DriverModule.sys"
    };

    for (const auto& candidate : candidates) {
        if (IsFileExists(candidate)) {
            return candidate;
        }
    }
    return L"";
}

static HANDLE OpenDriverDevice() {
    return CreateFileW(L"\\\\.\\PebMonitor", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

static HANDLE OpenDriverDeviceOverlapped() {
    return CreateFileW(L"\\\\.\\PebMonitor", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
}

static std::wstring ResolveTargetProcessNameForResponse(
    DWORD processId,
    const std::wstring& processNameHint) {
    if (!processNameHint.empty()) {
        return ToLowerCopy(processNameHint);
    }

    const std::wstring cachedName = GetCachedProcessName(processId);
    if (!cachedName.empty()) {
        return ToLowerCopy(cachedName);
    }

    return ToLowerCopy(GetProcessNameByPid(processId));
}

static void PruneAutoTerminateHistoryLocked(ULONGLONG nowTick) {
    for (std::unordered_map<DWORD, ULONGLONG>::iterator it = g_AutoTerminateHistory.begin();
        it != g_AutoTerminateHistory.end();) {
        if (nowTick - it->second > kAutoTerminateHistoryRetentionMs) {
            it = g_AutoTerminateHistory.erase(it);
        }
        else {
            ++it;
        }
    }

    while (g_AutoTerminateHistory.size() > kMaxAutoTerminateHistoryEntries) {
        std::unordered_map<DWORD, ULONGLONG>::iterator oldestIt = g_AutoTerminateHistory.begin();
        for (std::unordered_map<DWORD, ULONGLONG>::iterator it = g_AutoTerminateHistory.begin();
            it != g_AutoTerminateHistory.end();
            ++it) {
            if (it->second < oldestIt->second) {
                oldestIt = it;
            }
        }
        g_AutoTerminateHistory.erase(oldestIt);
    }
}

static bool ReserveAutoTerminateAttempt(DWORD processId, ULONG cooldownMs) {
    if (processId == 0) {
        return false;
    }

    if (cooldownMs == 0) {
        return true;
    }

    const ULONGLONG nowTick = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_AutoResponseLock);
    PruneAutoTerminateHistoryLocked(nowTick);

    std::unordered_map<DWORD, ULONGLONG>::const_iterator it = g_AutoTerminateHistory.find(processId);
    if (it != g_AutoTerminateHistory.end() &&
        nowTick >= it->second &&
        nowTick - it->second < cooldownMs) {
        return false;
    }

    g_AutoTerminateHistory[processId] = nowTick;
    return true;
}

static void MaybeAutoTerminateProcessForDriverEvent(
    const DRIVER_EVENT& driverEvent,
    const std::wstring& processName,
    const std::wstring& ruleId,
    const std::wstring& threatDesc,
    int severity,
    const std::wstring& targetPath,
    const std::wstring& registryOperation) {
    if (driverEvent.ProcessId == 0 ||
        driverEvent.ProcessId == GetCurrentProcessId() ||
        driverEvent.EventType != DRIVER_EVENT_TYPE_BLOCKED_REGISTRY_OPERATION) {
        return;
    }

    const RuleConfiguration config = g_RuleManager.GetRuleConfigurationSnapshot();
    if (!config.autoResponse.terminateOnRegistryBlock || severity < config.autoResponse.minSeverity) {
        return;
    }

    if (!ReserveAutoTerminateAttempt(driverEvent.ProcessId, config.autoResponse.cooldownMs)) {
        return;
    }

    const std::wstring resolvedProcessName =
        ResolveTargetProcessNameForResponse(driverEvent.ProcessId, processName);
    const std::wstring triggerEventType = DriverEventTypeToString(driverEvent.EventType);

    json requestEvent = BuildBaseJsonEvent("response_auto_terminate_requested", "warn", config);
    requestEvent["response_action"] = "terminate_process";
    requestEvent["response_mode"] = "auto";
    requestEvent["target_pid"] = driverEvent.ProcessId;
    requestEvent["target_process_name"] = WStringToUtf8(resolvedProcessName);
    requestEvent["trigger_driver_event_type"] = WStringToUtf8(triggerEventType);
    requestEvent["trigger_severity"] = severity;
    requestEvent["cooldown_ms"] = config.autoResponse.cooldownMs;
    requestEvent["exit_status"] = static_cast<unsigned long>(kDefaultTerminateExitStatus);
    requestEvent["registry_operation"] = WStringToUtf8(registryOperation);
    if (!ruleId.empty()) {
        requestEvent["trigger_rule_id"] = WStringToUtf8(ruleId);
    }
    if (!threatDesc.empty()) {
        requestEvent["trigger_threat_desc"] = WStringToUtf8(threatDesc);
    }
    if (!targetPath.empty()) {
        requestEvent["trigger_target_path"] = WStringToUtf8(targetPath);
    }
    EmitJsonEvent(requestEvent);

    HANDLE hDevice = OpenDriverDevice();
    if (hDevice == INVALID_HANDLE_VALUE) {
        const DWORD errorCode = GetLastError();
        LogMessage(
            L"[!] 自动终止响应失败：无法连接驱动设备，PID=" +
            std::to_wstring(driverEvent.ProcessId) +
            L", 错误码=" + std::to_wstring(errorCode));

        json resultEvent = BuildBaseJsonEvent("response_auto_terminate_result", "warn", config);
        resultEvent["response_action"] = "terminate_process";
        resultEvent["response_mode"] = "auto";
        resultEvent["target_pid"] = driverEvent.ProcessId;
        resultEvent["target_process_name"] = WStringToUtf8(resolvedProcessName);
        resultEvent["trigger_driver_event_type"] = WStringToUtf8(triggerEventType);
        resultEvent["trigger_severity"] = severity;
        resultEvent["success"] = false;
        resultEvent["win32_error"] = errorCode;
        resultEvent["reason"] = "open_driver_device_failed";
        EmitJsonEvent(resultEvent);
        return;
    }

    DWORD errorCode = ERROR_SUCCESS;
    bool terminated = TerminateTargetProcess(
        hDevice,
        driverEvent.ProcessId,
        kDefaultTerminateExitStatus,
        &errorCode);
    CloseHandle(hDevice);

    LogMessage(
        terminated
        ? (L"[+] 已根据注册表阻断事件自动终止目标进程，PID=" + std::to_wstring(driverEvent.ProcessId))
        : (L"[!] 注册表阻断触发自动终止失败，PID=" + std::to_wstring(driverEvent.ProcessId) +
            L", 错误码=" + std::to_wstring(errorCode)));

    json resultEvent = BuildBaseJsonEvent(
        "response_auto_terminate_result",
        terminated ? "info" : "warn",
        config);
    resultEvent["response_action"] = "terminate_process";
    resultEvent["response_mode"] = "auto";
    resultEvent["target_pid"] = driverEvent.ProcessId;
    resultEvent["target_process_name"] = WStringToUtf8(resolvedProcessName);
    resultEvent["trigger_driver_event_type"] = WStringToUtf8(triggerEventType);
    resultEvent["trigger_severity"] = severity;
    resultEvent["success"] = terminated;
    resultEvent["exit_status"] = static_cast<unsigned long>(kDefaultTerminateExitStatus);
    resultEvent["registry_operation"] = WStringToUtf8(registryOperation);
    if (!ruleId.empty()) {
        resultEvent["trigger_rule_id"] = WStringToUtf8(ruleId);
    }
    if (!threatDesc.empty()) {
        resultEvent["trigger_threat_desc"] = WStringToUtf8(threatDesc);
    }
    if (!targetPath.empty()) {
        resultEvent["trigger_target_path"] = WStringToUtf8(targetPath);
    }
    if (!terminated) {
        resultEvent["win32_error"] = errorCode;
    }
    EmitJsonEvent(resultEvent);
}
static bool IsPortOperationCancelled(HRESULT hr) {
    return hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) ||
        hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE);
}

static bool IsProcessReplyExpired(HRESULT hr) {
    return hr == HRESULT_FROM_WIN32(ERROR_FLT_NO_WAITER_FOR_REPLY) ||
        hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}

static std::wstring FormatHResult(HRESULT hr) {
    wchar_t buffer[32] = {};
    swprintf_s(buffer, RTL_NUMBER_OF(buffer), L"0x%08X", static_cast<unsigned int>(hr));
    return std::wstring(buffer);
}

static HRESULT ConnectProcessVerdictPort(HANDLE& hPort) {
    hPort = INVALID_HANDLE_VALUE;
    return FilterConnectCommunicationPort(
        PEBMONITOR_PROCESS_PORT_NAME,
        0,
        NULL,
        0,
        NULL,
        &hPort);
}

static std::wstring GetCurrentExePath() {
    wchar_t path[MAX_PATH] = {};
    if (GetModuleFileNameW(NULL, path, RTL_NUMBER_OF(path)) == 0) {
        return L"";
    }

    return std::wstring(path);
}

static std::wstring ServiceStateToString(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED:
        return L"stopped";
    case SERVICE_START_PENDING:
        return L"start_pending";
    case SERVICE_STOP_PENDING:
        return L"stop_pending";
    case SERVICE_RUNNING:
        return L"running";
    default:
        return L"state_" + std::to_wstring(state);
    }
}

static bool TryParseProcessId(const wchar_t* text, DWORD& processId) {
    processId = 0;
    if (text == NULL || text[0] == L'\0') {
        return false;
    }

    wchar_t* end = NULL;
    unsigned long parsed = wcstoul(text, &end, 10);
    if (end == text || (end != NULL && *end != L'\0') || parsed == 0 || parsed > MAXDWORD) {
        return false;
    }

    processId = static_cast<DWORD>(parsed);
    return true;
}

static int RunStatusCommand(const std::wstring& rulesPath, bool jsonOutput) {
    RuleConfiguration pendingConfig;
    std::wstring loadError;
    const bool loadSucceeded = g_RuleManager.TryLoadRulesFromJson(rulesPath, pendingConfig, &loadError);
    if (loadSucceeded) {
        SetLogRuleContext(pendingConfig.profileName, pendingConfig.configVersion, pendingConfig.generatedAt);
    }

    std::wstring dataDirectory = GetHostGuardDataDirectory();
    DWORD hostGuardServiceState = SERVICE_STOPPED;
    bool hostGuardServiceExists = false;
    bool hostGuardServiceStateAvailable =
        QueryWin32ServiceState(kHostGuardServiceName, hostGuardServiceState, hostGuardServiceExists);

    DWORD driverServiceState = SERVICE_STOPPED;
    bool driverServiceExists = false;
    bool driverServiceStateAvailable =
        QueryKernelDriverServiceState(kDriverServiceName, driverServiceState, driverServiceExists);

    std::wstring localDriverPath = FindLocalDriverPath();
    HANDLE hDevice = OpenDriverDevice();

    if (jsonOutput) {
        json statusJson = json::object();
        statusJson["command"] = "status";
        statusJson["output_mode"] = "json";
        statusJson["rules_path"] = WStringToUtf8(rulesPath);
        if (!dataDirectory.empty()) {
            statusJson["data_directory"] = WStringToUtf8(dataDirectory);
        }

        statusJson["rules_loaded"] = loadSucceeded;
        if (!loadSucceeded) {
            statusJson["rules_error"] =
                WStringToUtf8(loadError.empty() ? L"rules_load_failed" : loadError);
            statusJson["rules_file_exists"] = IsFileExists(rulesPath);
        }
        else {
            json ruleSummary = json::object();
            AppendPrefixedConfigFields(ruleSummary, pendingConfig, nullptr);
            ruleSummary["process_rule_count"] = pendingConfig.processRules.size();
            ruleSummary["process_allow_rule_count"] = pendingConfig.processAllowRules.size();
            ruleSummary["registry_rule_count"] = pendingConfig.registryRuleDefinitions.size();
            ruleSummary["registry_allow_rule_count"] = pendingConfig.registryAllowRuleDefinitions.size();

            json registryBlockClasses = json::object();
            AppendRegistryRuleClassStatsFields(registryBlockClasses, pendingConfig.registryRuleClassStats, nullptr);
            ruleSummary["registry_rule_classes"] = registryBlockClasses;

            json registryAllowClasses = json::object();
            AppendRegistryRuleClassStatsFields(registryAllowClasses, pendingConfig.registryAllowRuleClassStats, nullptr);
            ruleSummary["registry_allow_rule_classes"] = registryAllowClasses;

            statusJson["rule_summary"] = ruleSummary;
        }

        json servicesJson = json::object();
        servicesJson["hostguard_service_query_ok"] = hostGuardServiceStateAvailable;
        servicesJson["hostguard_service_exists"] = hostGuardServiceExists;
        if (hostGuardServiceStateAvailable) {
            servicesJson["hostguard_service_state"] = WStringToUtf8(ServiceStateToString(hostGuardServiceState));
        }

        servicesJson["driver_service_query_ok"] = driverServiceStateAvailable;
        servicesJson["driver_service_exists"] = driverServiceExists;
        if (driverServiceStateAvailable) {
            servicesJson["driver_service_state"] = WStringToUtf8(ServiceStateToString(driverServiceState));
        }

        statusJson["services"] = servicesJson;
        if (!localDriverPath.empty()) {
            statusJson["local_driver_path"] = WStringToUtf8(localDriverPath);
        }

        if (hDevice == INVALID_HANDLE_VALUE) {
            statusJson["driver_connected"] = false;
            statusJson["driver_error_code"] = GetLastError();
            std::cout << statusJson.dump(2) << std::endl;
            return 0;
        }

        DRIVER_RUNTIME_STATUS status = {};
        if (QueryDriverStatus(hDevice, status)) {
            statusJson["driver_connected"] = true;
            statusJson["driver_status"] = BuildDriverStatusJson(status);
        }
        else {
            statusJson["driver_connected"] = false;
            statusJson["driver_error_code"] = GetLastError();
        }

        CloseHandle(hDevice);
        std::cout << statusJson.dump(2) << std::endl;
        return 0;
    }

    LogMessage(L"[*] 正在执行状态检查...");
    LogMessage(L"[*] 规则文件路径: " + rulesPath);
    if (!dataDirectory.empty()) {
        LogMessage(L"[*] 预期数据目录: " + dataDirectory);
    }

    if (!loadSucceeded) {
        if (IsFileExists(rulesPath)) {
            LogMessage(L"[!] rules.json 存在但解析失败: " + loadError);
        }
        else {
            LogMessage(L"[!] 未找到可用的 rules.json。");
        }
    }
    else {
        LogConfigSummary(pendingConfig);
    }

    if (hostGuardServiceStateAvailable) {
        if (hostGuardServiceExists) {
            LogMessage(L"[+] HostGuard 服务状态: " + ServiceStateToString(hostGuardServiceState));
        }
        else {
            LogMessage(L"[!] HostGuard 服务不存在: " + std::wstring(kHostGuardServiceName));
        }
    }

    if (driverServiceStateAvailable) {
        if (driverServiceExists) {
            LogMessage(L"[+] 驱动服务状态: " + ServiceStateToString(driverServiceState));
        }
        else {
            LogMessage(L"[!] 驱动服务不存在: " + std::wstring(kDriverServiceName));
        }
    }

    if (!localDriverPath.empty()) {
        LogMessage(L"[+] 当前目录驱动文件: " + localDriverPath);
    }
    else {
        LogMessage(L"[!] 当前目录未找到 PebMonitor.sys 或 DriverModule.sys。");
    }

    if (hDevice == INVALID_HANDLE_VALUE) {
        LogMessage(L"[!] 当前无法连接驱动设备，错误码: " + std::to_wstring(GetLastError()));
        return 0;
    }

    QueryAndLogDriverStatus(hDevice);
    CloseHandle(hDevice);
    return 0;
}

static int RunInstallServiceCommand() {
    std::wstring exePath = GetCurrentExePath();
    if (exePath.empty()) {
        std::wcerr << L"[-] 错误：无法获取当前可执行文件路径。" << std::endl;
        return 1;
    }

    std::wstring binaryPath = L"\"" + exePath + L"\"";
    if (!InstallWin32Service(
        kHostGuardServiceName,
        kHostGuardDisplayName,
        binaryPath,
        SERVICE_AUTO_START)) {
        return 1;
    }

    std::wcout << L"[+] HostGuard 服务安装成功: " << kHostGuardServiceName << std::endl;
    return 0;
}

static int RunStartServiceCommand() {
    if (!StartWin32Service(kHostGuardServiceName)) {
        return 1;
    }

    std::wcout << L"[+] HostGuard 服务已启动。" << std::endl;
    return 0;
}

static int RunStopServiceCommand() {
    if (!StopWin32Service(kHostGuardServiceName)) {
        return 1;
    }

    std::wcout << L"[+] HostGuard 服务已停止。" << std::endl;
    return 0;
}

static int RunUninstallServiceCommand() {
    if (!RemoveWin32Service(kHostGuardServiceName)) {
        return 1;
    }

    std::wcout << L"[+] HostGuard 服务已卸载。" << std::endl;
    return 0;
}

static int RunTerminateProcessCommand(const wchar_t* pidText) {
    DWORD processId = 0;
    if (!TryParseProcessId(pidText, processId)) {
        std::wcerr << L"[-] 错误：请提供有效的十进制 PID，例如：HostGuard.exe terminate 1234" << std::endl;
        return 1;
    }

    const std::wstring processName = GetProcessNameByPid(processId);

    json requestEvent = BuildBaseJsonEvent("response_terminate_requested", "warn");
    requestEvent["response_action"] = "terminate_process";
    requestEvent["target_pid"] = processId;
    requestEvent["target_process_name"] = WStringToUtf8(processName);
    requestEvent["exit_status"] = static_cast<unsigned long>(kDefaultTerminateExitStatus);
    EmitJsonEvent(requestEvent);

    HANDLE hDevice = OpenDriverDevice();
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] 错误：无法连接驱动设备 (错误码: " << GetLastError() << L")" << std::endl;

        json resultEvent = BuildBaseJsonEvent("response_terminate_result", "warn");
        resultEvent["response_action"] = "terminate_process";
        resultEvent["target_pid"] = processId;
        resultEvent["target_process_name"] = WStringToUtf8(processName);
        resultEvent["success"] = false;
        resultEvent["win32_error"] = GetLastError();
        resultEvent["reason"] = "open_driver_device_failed";
        EmitJsonEvent(resultEvent);
        return 1;
    }

    DWORD errorCode = ERROR_SUCCESS;
    bool terminated = TerminateTargetProcess(hDevice, processId, kDefaultTerminateExitStatus, &errorCode);
    CloseHandle(hDevice);

    json resultEvent = BuildBaseJsonEvent("response_terminate_result", terminated ? "info" : "warn");
    resultEvent["response_action"] = "terminate_process";
    resultEvent["target_pid"] = processId;
    resultEvent["target_process_name"] = WStringToUtf8(processName);
    resultEvent["success"] = terminated;
    resultEvent["exit_status"] = static_cast<unsigned long>(kDefaultTerminateExitStatus);
    if (!terminated) {
        resultEvent["win32_error"] = errorCode;
    }
    EmitJsonEvent(resultEvent);

    if (!terminated) {
        return 1;
    }

    std::wcout << L"[+] 已向驱动下发终止请求，PID=" << processId << std::endl;
    return 0;
}

static bool ShouldFallbackToLegacyRegistryRuleSync(DWORD errorCode) {
    return errorCode == ERROR_INVALID_FUNCTION ||
        errorCode == ERROR_NOT_SUPPORTED ||
        errorCode == ERROR_CALL_NOT_IMPLEMENTED;
}

static bool ApplyRegistryRulesLegacy(HANDLE hDevice, const RuleConfiguration& config) {
    if (!ClearRegistryRules(hDevice)) {
        LogMessage(L"[!] 警告：清空驱动注册表规则失败，继续尝试下发配置中的规则。");
    }

    if (!ClearRegistryAllowRules(hDevice)) {
        LogMessage(L"[!] 警告：清空驱动注册表白名单失败，继续尝试下发配置中的规则。");
    }

    bool allSucceeded = true;
    for (std::vector<REGISTRY_RULE>::const_iterator it = config.registryRules.begin();
        it != config.registryRules.end();
        ++it) {
        if (!AddRegistryRule(hDevice, *it)) {
            allSucceeded = false;
        }
    }

    for (std::vector<REGISTRY_RULE>::const_iterator it = config.registryAllowRules.begin();
        it != config.registryAllowRules.end();
        ++it) {
        if (!AddRegistryAllowRule(hDevice, *it)) {
            allSucceeded = false;
        }
    }

    LogMessage(L"[+] 已同步注册表拦截规则数量: " + std::to_wstring(config.registryRules.size()));
    LogMessage(L"[+] 已同步注册表白名单规则数量: " + std::to_wstring(config.registryAllowRules.size()));
    return allSucceeded;
}

static bool ApplyRegistryRules(HANDLE hDevice, const RuleConfiguration& config) {
    LogRegistryRuleClassStats(L"[*] 注册表规则分类[kernel/block]", config.registryRuleClassStats);
    LogRegistryRuleClassStats(L"[*] 注册表规则分类[kernel/allow]", config.registryAllowRuleClassStats);

    DWORD replaceBlockError = ERROR_SUCCESS;
    if (!ReplaceRegistryRules(hDevice, config.registryRules, &replaceBlockError)) {
        if (ShouldFallbackToLegacyRegistryRuleSync(replaceBlockError)) {
            LogMessage(L"[!] 驱动不支持批量注册表规则替换，回退到逐条兼容下发模式。");
            return ApplyRegistryRulesLegacy(hDevice, config);
        }

        LogMessage(L"[!] 批量同步注册表拦截规则失败，错误码: " + std::to_wstring(replaceBlockError));
        return false;
    }

    DWORD replaceAllowError = ERROR_SUCCESS;
    if (!ReplaceRegistryAllowRules(hDevice, config.registryAllowRules, &replaceAllowError)) {
        if (ShouldFallbackToLegacyRegistryRuleSync(replaceAllowError)) {
            LogMessage(L"[!] 驱动不支持批量注册表白名单替换，回退到逐条兼容下发模式。");
            return ApplyRegistryRulesLegacy(hDevice, config);
        }

        LogMessage(L"[!] 批量同步注册表白名单规则失败，错误码: " + std::to_wstring(replaceAllowError));
        return false;
    }

    LogMessage(L"[+] 已批量同步注册表拦截规则数量: " + std::to_wstring(config.registryRules.size()));
    LogMessage(L"[+] 已批量同步注册表白名单规则数量: " + std::to_wstring(config.registryAllowRules.size()));
    return true;
}

static bool SyncDriverConfigInfo(HANDLE hDevice, const RuleConfiguration& config) {
    if (!SetActiveDriverConfigInfo(
        hDevice,
        config.configVersion,
        config.profileName,
        config.generatedAt,
        config.processVerdictTimeoutMs,
        config.processVerdictFailMode,
        config.captureParentCommandLine)) {
        LogMessage(L"[!] 警告：驱动配置版本同步失败。");
        return false;
    }

    return true;
}
static bool ApplyKernelRules(HANDLE hDevice, const RuleConfiguration& config) {
    bool registryRulesOk = ApplyRegistryRules(hDevice, config);
    bool configInfoOk = SyncDriverConfigInfo(hDevice, config);

    if (registryRulesOk && configInfoOk) {
        QueryAndLogDriverStatus(hDevice);
    }

    return registryRulesOk && configInfoOk;
}
static bool ApplyKernelRules(HANDLE hDevice) {
    RuleConfiguration activeConfig = g_RuleManager.GetRuleConfigurationSnapshot();
    return ApplyKernelRules(hDevice, activeConfig);
}

static bool ApplyKernelRulesWithFreshHandle(const RuleConfiguration& config) {
    HANDLE hDevice = OpenDriverDevice();
    if (hDevice == INVALID_HANDLE_VALUE) {
        LogMessage(L"[!] 当前无法连接驱动设备，内核拦截规则更新将延迟到下次连接恢复后再同步。");
        return false;
    }

    bool success = ApplyKernelRules(hDevice, config);
    CloseHandle(hDevice);
    return success;
}

static bool ReloadRulesFromDisk(
    const std::wstring& rulesPath,
    bool applyDriverRulesAfterLoad,
    bool isHotReload = false) {
    const RuleConfiguration previousConfig = g_RuleManager.GetRuleConfigurationSnapshot();

    if (isHotReload) {
        json startEvent = BuildBaseJsonEvent("config_reload_started", "info", previousConfig);
        startEvent["action"] = "reload";
        startEvent["result"] = "started";
        startEvent["trigger"] = "rules_file_changed";
        startEvent["rules_path"] = WStringToUtf8(rulesPath);
        AppendPrefixedConfigFields(startEvent, previousConfig, "previous_");
        EmitJsonEvent(startEvent);
    }

    RuleConfiguration pendingConfig;
    std::wstring loadError;
    if (!g_RuleManager.TryLoadRulesFromJson(rulesPath, pendingConfig, &loadError)) {
        if (!loadError.empty()) {
            LogMessage(L"[!] rules.json 解析失败: " + loadError);
        }

        if (isHotReload) {
            LogMessage(L"[!] rules.json 热更新解析失败，已回滚并继续保留旧配置: " + DescribeConfigIdentity(previousConfig));

            json rollbackEvent = BuildBaseJsonEvent("config_reload_rollback", "warn", previousConfig);
            rollbackEvent["action"] = "reload";
            rollbackEvent["result"] = "rollback_retained";
            rollbackEvent["reload_stage"] = "parse";
            rollbackEvent["rules_path"] = WStringToUtf8(rulesPath);
            rollbackEvent["error"] = WStringToUtf8(loadError.empty() ? L"unknown_parse_error" : loadError);
            AppendPrefixedConfigFields(rollbackEvent, previousConfig, "previous_");
            EmitJsonEvent(rollbackEvent);
        }

        return false;
    }

    if (applyDriverRulesAfterLoad && !ApplyKernelRulesWithFreshHandle(pendingConfig)) {
        if (isHotReload) {
            LogMessage(L"[!] rules.json 热更新内核同步失败，已回滚并继续保留旧配置: " + DescribeConfigIdentity(previousConfig));
            LogMessage(L"    └─ 候选配置: " + DescribeConfigIdentity(pendingConfig));

            json rollbackEvent = BuildBaseJsonEvent("config_reload_rollback", "warn", previousConfig);
            rollbackEvent["action"] = "reload";
            rollbackEvent["result"] = "rollback_retained";
            rollbackEvent["reload_stage"] = "kernel_sync";
            rollbackEvent["rules_path"] = WStringToUtf8(rulesPath);
            rollbackEvent["error"] = "kernel_rule_sync_failed";
            AppendPrefixedConfigFields(rollbackEvent, previousConfig, "previous_");
            AppendPrefixedConfigFields(rollbackEvent, pendingConfig, "candidate_");
            EmitJsonEvent(rollbackEvent);
        }
        else {
            LogMessage(L"[!] 候选配置未能成功同步到驱动，继续保留旧版本配置。");
        }

        return false;
    }

    g_RuleManager.ApplyLoadedRules(std::move(pendingConfig));
    RuleConfiguration activeConfig = g_RuleManager.GetRuleConfigurationSnapshot();
    SetLogRuleContext(activeConfig.profileName, activeConfig.configVersion, activeConfig.generatedAt);

    if (isHotReload && HasConfigIdentityChanged(previousConfig, activeConfig)) {
        LogMessage(L"[+] 规则版本变更: " + DescribeConfigIdentity(previousConfig) + L" -> " + DescribeConfigIdentity(activeConfig));

        json versionChangedEvent = BuildBaseJsonEvent("config_version_changed", "info", activeConfig);
        versionChangedEvent["action"] = "reload";
        versionChangedEvent["result"] = "updated";
        versionChangedEvent["rules_path"] = WStringToUtf8(rulesPath);
        AppendPrefixedConfigFields(versionChangedEvent, previousConfig, "previous_");
        AppendPrefixedConfigFields(versionChangedEvent, activeConfig, "new_");
        EmitJsonEvent(versionChangedEvent);
    }

    LogConfigSummary(activeConfig);

    json configEvent = BuildBaseJsonEvent("config_applied", "info", activeConfig);
    configEvent["action"] = isHotReload ? "reload" : "load";
    configEvent["result"] = "success";
    configEvent["load_mode"] = isHotReload ? "hot_reload" : "initial";
    configEvent["process_rule_count"] = activeConfig.processRules.size();
    configEvent["process_allow_rule_count"] = activeConfig.processAllowRules.size();
    configEvent["registry_rule_count"] = activeConfig.registryRules.size();
    configEvent["registry_allow_rule_count"] = activeConfig.registryAllowRules.size();
    AppendRegistryRuleClassStatsFields(configEvent, activeConfig.registryRuleClassStats, "registry_rule_class_");
    AppendRegistryRuleClassStatsFields(configEvent, activeConfig.registryAllowRuleClassStats, "registry_allow_rule_class_");
    AppendPrefixedConfigFields(configEvent, activeConfig, "");
    if (isHotReload) {
        AppendPrefixedConfigFields(configEvent, previousConfig, "previous_");
    }
    EmitJsonEvent(configEvent);
    return true;
}

void RulesHotReloadThread(std::wstring rulesPath) {
    FileState lastState;
    QueryFileState(rulesPath, lastState);

    while (!WaitForShutdown(2000)) {
        FileState currentState;
        QueryFileState(rulesPath, currentState);
        if (IsSameFileState(lastState, currentState)) {
            continue;
        }

        lastState = currentState;
        if (!currentState.exists) {
            RuleConfiguration activeConfig = g_RuleManager.GetRuleConfigurationSnapshot();
            LogMessage(L"[!] 检测到 rules.json 被删除，继续保留当前已生效配置: " + DescribeConfigIdentity(activeConfig));

            json rollbackEvent = BuildBaseJsonEvent("config_reload_rollback", "warn", activeConfig);
            rollbackEvent["action"] = "reload";
            rollbackEvent["result"] = "rollback_retained";
            rollbackEvent["reload_stage"] = "file_missing";
            rollbackEvent["rules_path"] = WStringToUtf8(rulesPath);
            rollbackEvent["error"] = "rules_file_deleted";
            AppendPrefixedConfigFields(rollbackEvent, activeConfig, "previous_");
            EmitJsonEvent(rollbackEvent);
            continue;
        }

        LogMessage(L"[*] 检测到 rules.json 变化，开始热更新配置。");
        if (ReloadRulesFromDisk(rulesPath, true, true)) {
            LogMessage(L"[+] rules.json 热更新成功。");
        }
        else {
            LogMessage(L"[!] rules.json 热更新失败，继续保留旧配置。");
        }
    }
}

namespace {
    const DWORD kProcessPortWorkerCap = 16;
    const DWORD kProcessPortMinWorkers = 2;
    const DWORD kProcessPortOutstandingPerWorker = 2;
    const DWORD kProcessPortBackoffMinMs = 500;
    const DWORD kProcessPortBackoffMaxMs = 15000;
    const DWORD kDriverEventBackoffMinMs = 1000;
    const DWORD kDriverEventBackoffMaxMs = 15000;

    struct ProcessPortAsyncContext {
        OVERLAPPED overlapped;
        ProcessPortMessageBuffer message;
    };

    struct DriverEventAsyncContext {
        OVERLAPPED overlapped;
        DRIVER_EVENT driverEvent;
        DWORD bytesReturned;
    };

    ;
}

static bool IsProcessPortDisconnected(HRESULT hr) {
    return hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) ||
        hr == HRESULT_FROM_WIN32(ERROR_FLT_DELETING_OBJECT);
}

static DWORD QueryProcessPortWorkerCount() {
    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);

    DWORD workers = systemInfo.dwNumberOfProcessors * 2;
    if (workers < kProcessPortMinWorkers) {
        workers = kProcessPortMinWorkers;
    }
    if (workers > kProcessPortWorkerCap) {
        workers = kProcessPortWorkerCap;
    }
    return workers;
}

static HRESULT PostProcessPortReceive(
    HANDLE hProcessPort,
    ProcessPortAsyncContext& context) {
    ZeroMemory(&context.overlapped, sizeof(context.overlapped));
    ZeroMemory(&context.message, sizeof(context.message));

    HRESULT hr = FilterGetMessage(
        hProcessPort,
        &context.message.header,
        static_cast<DWORD>(sizeof(context.message)),
        &context.overlapped);

    if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING) || SUCCEEDED(hr)) {
        return S_OK;
    }

    return hr;
}

static bool HandleProcessVerdictMessage(
    HANDLE hProcessPort,
    const ProcessPortMessageBuffer& message,
    HRESULT& outFatalHr) {
    outFatalHr = S_OK;

    std::wstring parentImagePath(message.request.ParentImagePath);
    std::wstring childImagePath(message.request.ImagePath);
    std::wstring parentName = ExtractProcessNameFromImagePath(parentImagePath);
    std::wstring childName = ExtractProcessNameFromImagePath(childImagePath);
    std::wstring cmdLine(message.request.CommandLine);
    std::wstring parentCmdLine(message.request.ParentCommandLine);
    if (childName.empty()) {
        childName = GetCachedProcessName(message.request.ProcessId);
    }
    if (parentName.empty()) {
        parentName = GetCachedProcessName(message.request.ParentProcessId);
    }
    if (childName.empty()) {
        childName = L"<unknown>";
    }
    if (parentName.empty()) {
        parentName = L"<unknown>";
    }

    CacheProcessContext(message.request.ProcessId, childName, cmdLine, childImagePath);
    CacheProcessContext(message.request.ParentProcessId, parentName, parentCmdLine, parentImagePath);

    if (parentCmdLine.empty()) {
        parentCmdLine = GetCachedProcessCommandLine(message.request.ParentProcessId);
    }

    ProcessPortReplyBuffer reply = {};
    reply.header.MessageId = message.header.MessageId;
    reply.reply.Version = PROCESS_PORT_PROTOCOL_VERSION;
    reply.reply.BlockProcess = 0;

    DetectionRule matchedAllowRule;
    DetectionRule matchedRule;
    bool allowMatched = g_RuleManager.TryMatchProcessAllowRule(parentName, childName, cmdLine, parentCmdLine, matchedAllowRule);
    bool blockMatched = false;
    if (!allowMatched) {
        blockMatched = g_RuleManager.EvaluateProcessAgainstRules(parentName, childName, cmdLine, parentCmdLine, matchedRule);
        if (blockMatched) {
            reply.reply.BlockProcess = 1;
        }
    }

    HRESULT replyHr = FilterReplyMessage(
        hProcessPort,
        &reply.header,
        static_cast<DWORD>(sizeof(reply)));
    if (FAILED(replyHr)) {
        if (IsShutdownRequested() && IsPortOperationCancelled(replyHr)) {
            return false;
        }

        if (IsProcessReplyExpired(replyHr)) {
            LogMessage(L"[*] 进程裁决已过期，驱动已按超时策略继续执行。EventId=" +
                std::to_wstring(message.request.EventId) +
                L", PID=" +
                std::to_wstring(message.request.ProcessId));

            json expiredEvent = BuildBaseJsonEvent("process_verdict_expired", "info");
            expiredEvent["event_id"] = message.request.EventId;
            expiredEvent["process_id"] = message.request.ProcessId;
            expiredEvent["create_time"] = message.request.CreateTime;
            expiredEvent["parent_name"] = WStringToUtf8(parentName);
            expiredEvent["child_name"] = WStringToUtf8(childName);
            expiredEvent["command_line"] = WStringToUtf8(cmdLine);
            if (!parentCmdLine.empty()) {
                expiredEvent["parent_command_line"] = WStringToUtf8(parentCmdLine);
            }
            if (!parentImagePath.empty()) {
                expiredEvent["parent_image_path"] = WStringToUtf8(parentImagePath);
            }
            if (!childImagePath.empty()) {
                expiredEvent["child_image_path"] = WStringToUtf8(childImagePath);
            }
            expiredEvent["file_open_name_available"] =
                (message.request.Flags & PROCESS_PORT_REQUEST_FLAG_FILE_OPEN_NAME_AVAILABLE) != 0;
            expiredEvent["intended_action"] = reply.reply.BlockProcess != 0 ? "block" : "allow";
            if (blockMatched) {
                expiredEvent["rule_id"] = WStringToUtf8(matchedRule.id);
                expiredEvent["severity"] = matchedRule.severity;
            }
            EmitJsonEvent(expiredEvent);
            return true;
        }

        LogMessage(L"[!] 向驱动发送进程判决失败，HRESULT=" + FormatHResult(replyHr));
        outFatalHr = replyHr;
        return false;
    }

    if (allowMatched) {
        LogMessage(L"[+] 命中进程白名单，跳过拦截。");
        LogMessage(L"    └─ 白名单 ID: " + matchedAllowRule.id);
        LogMessage(L"    └─ EventId: " + std::to_wstring(message.request.EventId));
        LogMessage(L"    └─ 父进程名: " + parentName);
        LogMessage(L"    └─ 子进程名: " + childName);
        if (!parentImagePath.empty()) {
            LogMessage(L"    └─ 父进程路径: " + parentImagePath);
        }
        if (!childImagePath.empty()) {
            LogMessage(L"    └─ 子进程路径: " + childImagePath);
        }
        if (!parentCmdLine.empty()) {
            LogMessage(L"    └─ 父进程命令行: " + parentCmdLine);
        }
        LogMessage(L"    └─ 命令行: " + cmdLine);

        json allowEvent = BuildBaseJsonEvent("process_allow", "info");
        allowEvent["event_id"] = message.request.EventId;
        allowEvent["process_id"] = message.request.ProcessId;
        allowEvent["create_time"] = message.request.CreateTime;
        allowEvent["rule_id"] = WStringToUtf8(matchedAllowRule.id);
        allowEvent["severity"] = matchedAllowRule.severity;
        allowEvent["parent_name"] = WStringToUtf8(parentName);
        allowEvent["child_name"] = WStringToUtf8(childName);
        allowEvent["command_line"] = WStringToUtf8(cmdLine);
        if (!parentImagePath.empty()) {
            allowEvent["parent_image_path"] = WStringToUtf8(parentImagePath);
        }
        if (!childImagePath.empty()) {
            allowEvent["child_image_path"] = WStringToUtf8(childImagePath);
        }
        allowEvent["file_open_name_available"] =
            (message.request.Flags & PROCESS_PORT_REQUEST_FLAG_FILE_OPEN_NAME_AVAILABLE) != 0;
        if (!parentCmdLine.empty()) {
            allowEvent["parent_command_line"] = WStringToUtf8(parentCmdLine);
        }
        EmitJsonEvent(allowEvent);
    }
    else if (blockMatched) {
        LogMessage(L"[!] ==================================================");
        LogMessage(L"[!] 触发规则 ID: " + matchedRule.id);
        LogMessage(L"[!] EventId: " + std::to_wstring(message.request.EventId));
        LogMessage(L"[!] 威胁描述: " + matchedRule.threatDesc);
        LogMessage(L"[!] 父进程名: " + parentName);
        LogMessage(L"[!] 子进程名: " + childName);
        if (!parentImagePath.empty()) {
            LogMessage(L"[!] 父进程路径: " + parentImagePath);
        }
        if (!childImagePath.empty()) {
            LogMessage(L"[!] 子进程路径: " + childImagePath);
        }
        if (!parentCmdLine.empty()) {
            LogMessage(L"[!] 父进程命令行: " + parentCmdLine);
        }
        LogMessage(L"[!] 命中的命令行: " + cmdLine);
        LogMessage(L"[!] 执行动作: 拦截 (Severity: " + std::to_wstring(matchedRule.severity) + L")");
        LogMessage(L"[!] ==================================================");

        json blockEvent = BuildBaseJsonEvent("process_block", "warn");
        blockEvent["event_id"] = message.request.EventId;
        blockEvent["process_id"] = message.request.ProcessId;
        blockEvent["create_time"] = message.request.CreateTime;
        blockEvent["rule_id"] = WStringToUtf8(matchedRule.id);
        blockEvent["threat_desc"] = WStringToUtf8(matchedRule.threatDesc);
        blockEvent["severity"] = matchedRule.severity;
        blockEvent["parent_name"] = WStringToUtf8(parentName);
        blockEvent["child_name"] = WStringToUtf8(childName);
        blockEvent["command_line"] = WStringToUtf8(cmdLine);
        if (!parentImagePath.empty()) {
            blockEvent["parent_image_path"] = WStringToUtf8(parentImagePath);
        }
        if (!childImagePath.empty()) {
            blockEvent["child_image_path"] = WStringToUtf8(childImagePath);
        }
        blockEvent["file_open_name_available"] =
            (message.request.Flags & PROCESS_PORT_REQUEST_FLAG_FILE_OPEN_NAME_AVAILABLE) != 0;
        if (!parentCmdLine.empty()) {
            blockEvent["parent_command_line"] = WStringToUtf8(parentCmdLine);
        }
        EmitJsonEvent(blockEvent);
    }

    return true;
}

void HeartbeatMonitorThread() {
    bool wasConnected = false;

    while (!IsShutdownRequested()) {
        HANDLE hHeartbeatDevice = OpenDriverDevice();
        if (hHeartbeatDevice == INVALID_HANDLE_VALUE) {
            if (wasConnected) {
                LogMessage(L"[!] 进程裁决心跳通道断开，等待驱动设备恢复。");
                wasConnected = false;
            }

            if (WaitForShutdown(PROCESS_HEARTBEAT_INTERVAL_MS_DEFAULT)) {
                break;
            }
            continue;
        }

        TrackDeviceHandle(g_HeartbeatDeviceHandle, hHeartbeatDevice);
        if (!wasConnected) {
            LogMessage(L"[+] 进程裁决心跳线程已启动。");
            wasConnected = true;
        }

        while (!IsShutdownRequested()) {
            DWORD bytesReturned = 0;
            BOOL result = DeviceIoControl(
                hHeartbeatDevice,
                IOCTL_HIPS_HEARTBEAT,
                NULL,
                0,
                NULL,
                0,
                &bytesReturned,
                NULL);
            if (!result) {
                if (!IsShutdownRequested()) {
                    LogMessage(
                        L"[!] 进程裁决心跳发送失败，错误码: " +
                        std::to_wstring(GetLastError()));
                }
                break;
            }

            if (WaitForShutdown(PROCESS_HEARTBEAT_INTERVAL_MS_DEFAULT)) {
                break;
            }
        }

        CloseTrackedHandle(hHeartbeatDevice, g_HeartbeatDeviceHandle);
    }
}

void ProcessVerdictMonitorThread() {
    bool firstConnection = true;
    DWORD reconnectBackoffMs = kProcessPortBackoffMinMs;

    while (!IsShutdownRequested()) {
        HANDLE hProcessPort = INVALID_HANDLE_VALUE;
        HRESULT connectHr = ConnectProcessVerdictPort(hProcessPort);
        if (FAILED(connectHr)) {
            if (!IsShutdownRequested()) {
                LogMessage(L"[-] 进程裁决通信端口连接失败，" + std::to_wstring(reconnectBackoffMs) +
                    L"ms 后重试。HRESULT=" + FormatHResult(connectHr));
            }
            if (WaitForShutdown(reconnectBackoffMs)) {
                break;
            }
            reconnectBackoffMs =
                (reconnectBackoffMs >= (kProcessPortBackoffMaxMs / 2))
                ? kProcessPortBackoffMaxMs
                : (reconnectBackoffMs * 2);
            continue;
        }

        reconnectBackoffMs = kProcessPortBackoffMinMs;
        TrackDeviceHandle(g_ProcessPortHandle, hProcessPort);

        if (firstConnection) {
            LogMessage(L"[+] 进程裁决通信端口已连接，启用 IOCP 并行判定管线。");
            firstConnection = false;
        }
        else {
            RuleConfiguration activeConfig = g_RuleManager.GetRuleConfigurationSnapshot();
            if (ApplyKernelRulesWithFreshHandle(activeConfig)) {
                LogMessage(L"[+] 进程裁决端口重连成功，已重新同步当前内核规则。");
            }
            else {
                LogMessage(L"[!] 进程裁决端口已重连，但重新同步当前内核规则失败。");
            }
        }

        DWORD workerCount = QueryProcessPortWorkerCount();
        DWORD outstandingCount = workerCount * kProcessPortOutstandingPerWorker;
        if (outstandingCount == 0) {
            outstandingCount = kProcessPortMinWorkers;
        }

        HANDLE hIocp = CreateIoCompletionPort(hProcessPort, NULL, 0, workerCount);
        if (hIocp == NULL) {
            DWORD err = GetLastError();
            LogMessage(L"[!] 创建进程裁决 IOCP 失败，错误码: " + std::to_wstring(err));
            CloseTrackedHandle(hProcessPort, g_ProcessPortHandle);
            if (WaitForShutdown(reconnectBackoffMs)) {
                break;
            }
            reconnectBackoffMs =
                (reconnectBackoffMs >= (kProcessPortBackoffMaxMs / 2))
                ? kProcessPortBackoffMaxMs
                : (reconnectBackoffMs * 2);
            continue;
        }

        std::vector<ProcessPortAsyncContext> contexts(outstandingCount);
        bool postFailed = false;
        HRESULT postFailedHr = S_OK;
        for (DWORD i = 0; i < outstandingCount; ++i) {
            HRESULT hr = PostProcessPortReceive(hProcessPort, contexts[i]);
            if (FAILED(hr)) {
                postFailed = true;
                postFailedHr = hr;
                break;
            }
        }

        if (postFailed) {
            if (!IsPortOperationCancelled(postFailedHr)) {
                LogMessage(L"[!] 初始化异步接收失败，HRESULT=" + FormatHResult(postFailedHr));
            }
            CancelIoEx(hProcessPort, NULL);
            CloseHandle(hIocp);
            CloseTrackedHandle(hProcessPort, g_ProcessPortHandle);
            if (WaitForShutdown(reconnectBackoffMs)) {
                break;
            }
            reconnectBackoffMs =
                (reconnectBackoffMs >= (kProcessPortBackoffMaxMs / 2))
                ? kProcessPortBackoffMaxMs
                : (reconnectBackoffMs * 2);
            continue;
        }

        std::atomic<bool> connectionBroken(false);
        std::atomic<bool> cancellationIssued(false);
        std::mutex fatalLock;
        HRESULT fatalHr = S_OK;

        auto setConnectionBroken = [&](HRESULT hr) {
            {
                std::lock_guard<std::mutex> guard(fatalLock);
                if (SUCCEEDED(fatalHr)) {
                    fatalHr = hr;
                }
            }

            connectionBroken.store(true, std::memory_order_release);
            bool expected = false;
            if (cancellationIssued.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                CancelIoEx(hProcessPort, NULL);
            }
        };

        std::vector<std::thread> workers;
        workers.reserve(workerCount);
        for (DWORD i = 0; i < workerCount; ++i) {
            workers.emplace_back([&, i]() {
                UNREFERENCED_PARAMETER(i);
                while (!IsShutdownRequested() &&
                    !connectionBroken.load(std::memory_order_acquire)) {
                    DWORD transferred = 0;
                    ULONG_PTR completionKey = 0;
                    LPOVERLAPPED overlapped = NULL;
                    BOOL ok = GetQueuedCompletionStatus(
                        hIocp,
                        &transferred,
                        &completionKey,
                        &overlapped,
                        500);
                    UNREFERENCED_PARAMETER(completionKey);

                    if (overlapped == NULL) {
                        if (!ok && GetLastError() == WAIT_TIMEOUT) {
                            continue;
                        }
                        if (!ok) {
                            setConnectionBroken(HRESULT_FROM_WIN32(GetLastError()));
                        }
                        continue;
                    }

                    ProcessPortAsyncContext* context =
                        CONTAINING_RECORD(overlapped, ProcessPortAsyncContext, overlapped);

                    HRESULT receiveHr = ok ? S_OK : HRESULT_FROM_WIN32(GetLastError());
                    if (FAILED(receiveHr)) {
                        if (!(IsShutdownRequested() && IsPortOperationCancelled(receiveHr))) {
                            if (!IsPortOperationCancelled(receiveHr)) {
                                setConnectionBroken(receiveHr);
                            }
                        }
                        continue;
                    }

                    HRESULT fatalReplyHr = S_OK;
                    bool handled = HandleProcessVerdictMessage(hProcessPort, context->message, fatalReplyHr);
                    if (!handled) {
                        if (!(IsShutdownRequested() && IsPortOperationCancelled(fatalReplyHr))) {
                            if (!IsPortOperationCancelled(fatalReplyHr)) {
                                setConnectionBroken(fatalReplyHr);
                            }
                        }
                        continue;
                    }

                    if (!IsShutdownRequested() &&
                        !connectionBroken.load(std::memory_order_acquire)) {
                        HRESULT repostHr = PostProcessPortReceive(hProcessPort, *context);
                        if (FAILED(repostHr) &&
                            !(IsShutdownRequested() && IsPortOperationCancelled(repostHr)) &&
                            !IsPortOperationCancelled(repostHr)) {
                            setConnectionBroken(repostHr);
                        }
                    }
                }
                });
        }

        while (!IsShutdownRequested() &&
            !connectionBroken.load(std::memory_order_acquire)) {
            Sleep(200);
        }

        bool expected = false;
        if (cancellationIssued.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            CancelIoEx(hProcessPort, NULL);
        }

        for (std::thread& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }

        CloseHandle(hIocp);
        CloseTrackedHandle(hProcessPort, g_ProcessPortHandle);

        HRESULT brokenHr = S_OK;
        {
            std::lock_guard<std::mutex> guard(fatalLock);
            brokenHr = fatalHr;
        }

        if (!IsShutdownRequested() &&
            FAILED(brokenHr) &&
            !IsPortOperationCancelled(brokenHr) &&
            !IsProcessReplyExpired(brokenHr)) {
            if (IsProcessPortDisconnected(brokenHr)) {
                LogMessage(L"[!] 进程裁决通信端口断开，准备重连。HRESULT=" + FormatHResult(brokenHr));
            }
            else {
                LogMessage(L"[!] 进程裁决 IOCP 工作线程异常退出，准备重连。HRESULT=" + FormatHResult(brokenHr));
            }
        }
    }
}

static bool PostDriverEventReceive(HANDLE hDriverDevice, DriverEventAsyncContext& context) {
    ZeroMemory(&context.overlapped, sizeof(context.overlapped));
    ZeroMemory(&context.driverEvent, sizeof(context.driverEvent));
    context.bytesReturned = 0;

    BOOL issued = DeviceIoControl(
        hDriverDevice,
        IOCTL_GET_DRIVER_EVENT,
        NULL,
        0,
        &context.driverEvent,
        sizeof(context.driverEvent),
        &context.bytesReturned,
        &context.overlapped);

    if (issued) {
        return true;
    }

    DWORD err = GetLastError();
    return err == ERROR_IO_PENDING;
}

static void HandleDriverEventPayload(const DRIVER_EVENT& driverEvent) {
    std::wstring targetPath(driverEvent.TargetPath);
    std::wstring processName(driverEvent.ProcessName);
    std::wstring commandLine(driverEvent.CommandLine);
    std::wstring ruleId(driverEvent.RuleId);
    std::wstring infoClass(driverEvent.InfoClass);
    std::wstring valueName(driverEvent.ValueName);
    std::wstring valueData(driverEvent.ValueData);
    std::wstring threatDesc;
    int severity = static_cast<int>(driverEvent.Severity);
    DWORD parentProcessId = driverEvent.ParentProcessId;
    std::wstring registryOperation = RegistryOperationToString(driverEvent.RegistryOperation);
    std::wstring responseAction = ResponseActionToString(driverEvent.ResponseAction);
    std::wstring responseStatusText = FormatNtStatusHex(driverEvent.ResponseStatus);
    bool responseSucceeded = driverEvent.ResponseStatus >= 0;
    const bool isObservedProcessCreate = (driverEvent.EventType == DRIVER_EVENT_TYPE_OBSERVED_PROCESS_CREATE);
    const bool isBlockedFileOperation = (driverEvent.EventType == DRIVER_EVENT_TYPE_BLOCKED_FILE_OPERATION);
    const bool isDriverSelfProtection =
        isBlockedFileOperation &&
        !ruleId.empty() &&
        _wcsicmp(ruleId.c_str(), kDriverSelfProtectionRuleId) == 0;
    const bool isRegistryDriverEvent =
        (driverEvent.EventType == DRIVER_EVENT_TYPE_BLOCKED_REGISTRY_OPERATION) ||
        (driverEvent.EventType == DRIVER_EVENT_TYPE_OBSERVED_REGISTRY_OPERATION);
    const std::wstring driverEventTypeName = DriverEventTypeToString(driverEvent.EventType);
    std::wstring parentProcessName;

    if (isObservedProcessCreate && processName.empty() && !targetPath.empty()) {
        processName = ExtractProcessNameFromImagePath(targetPath);
    }
    if (isObservedProcessCreate) {
        CacheProcessContext(driverEvent.ProcessId, processName, commandLine, targetPath);
        if (parentProcessId != 0) {
            parentProcessName = GetCachedProcessName(parentProcessId);
        }
    }

    if (!ruleId.empty()) {
        int configuredSeverity = 0;
        if (g_RuleManager.TryGetRegistryRuleMetadata(ruleId, threatDesc, configuredSeverity) &&
            severity == 0) {
            severity = configuredSeverity;
        }
    }

    LogMessage(L"#########################################################");
    if (driverEvent.EventType == DRIVER_EVENT_TYPE_BLOCKED_REGISTRY_OPERATION) {
        LogMessage(L"[!] 已在注册表操作阶段阻止高危修改。");
        LogMessage(L"    └─ 操作类型: " + registryOperation);
        if (!ruleId.empty()) {
            LogMessage(L"    └─ 规则 ID: " + ruleId);
        }
        if (!threatDesc.empty()) {
            LogMessage(L"    └─ 威胁描述: " + threatDesc);
        }
        if (severity > 0) {
            LogMessage(L"    └─ Severity: " + std::to_wstring(severity));
        }
        if (!processName.empty()) {
            LogMessage(L"    └─ 发起进程: " + processName + L" (PID: " + std::to_wstring(driverEvent.ProcessId) + L")");
        }
        LogMessage(L"    └─ 注册表路径: " + targetPath);
        if (!infoClass.empty()) {
            LogMessage(L"    └─ InfoClass: " + infoClass);
        }
        if (!valueName.empty()) {
            LogMessage(L"    └─ 值名称: " + valueName);
        }
        if (!valueData.empty()) {
            if (driverEvent.RegistryOperation == REGISTRY_OPERATION_RENAME_KEY) {
                LogMessage(L"    └─ 新名称: " + valueData);
            }
            else {
                LogMessage(L"    └─ 值数据: " + valueData);
            }
        }
    }
    else if (driverEvent.EventType == DRIVER_EVENT_TYPE_OBSERVED_REGISTRY_OPERATION) {
        LogMessage(L"[*] 在监控模式下观测到命中规则的注册表操作，未执行阻断。");
        LogMessage(L"    └─ 操作类型: " + registryOperation);
        if (!ruleId.empty()) {
            LogMessage(L"    └─ 规则 ID: " + ruleId);
        }
        if (!threatDesc.empty()) {
            LogMessage(L"    └─ 威胁描述: " + threatDesc);
        }
        if (severity > 0) {
            LogMessage(L"    └─ Severity: " + std::to_wstring(severity));
        }
        if (!processName.empty()) {
            LogMessage(L"    └─ 发起进程: " + processName + L" (PID: " + std::to_wstring(driverEvent.ProcessId) + L")");
        }
        LogMessage(L"    └─ 注册表路径: " + targetPath);
        if (!infoClass.empty()) {
            LogMessage(L"    └─ InfoClass: " + infoClass);
        }
        if (!valueName.empty()) {
            LogMessage(L"    └─ 值名称: " + valueName);
        }
        if (!valueData.empty()) {
            if (driverEvent.RegistryOperation == REGISTRY_OPERATION_RENAME_KEY) {
                LogMessage(L"    └─ 新名称: " + valueData);
            }
            else {
                LogMessage(L"    └─ 值数据: " + valueData);
            }
        }
    }
    else if (isObservedProcessCreate) {
        LogMessage(L"[*] 在监控模式下观测到进程创建，未进入同步裁决链路。");
        LogMessage(L"    └─ 进程 PID: " + std::to_wstring(driverEvent.ProcessId));
        LogMessage(L"    └─ 父进程 PID: " + std::to_wstring(parentProcessId));
        if (!parentProcessName.empty()) {
            LogMessage(L"    └─ 父进程名: " + parentProcessName);
        }
        if (!processName.empty()) {
            LogMessage(L"    └─ 进程名: " + processName);
        }
        if (!targetPath.empty()) {
            LogMessage(L"    └─ 镜像路径: " + targetPath);
        }
        if (!commandLine.empty()) {
            LogMessage(L"    └─ 命令行: " + commandLine);
        }
    }
    else if (isBlockedFileOperation) {
        LogMessage(L"[!] 已阻止对受保护驱动文件的写入或删除访问。");
        if (isDriverSelfProtection) {
            LogMessage(L"    └─ 保护类别: driver_self_protection");
        }
        if (!ruleId.empty()) {
            LogMessage(L"    └─ 规则 ID: " + ruleId);
        }
        if (severity > 0) {
            LogMessage(L"    └─ Severity: " + std::to_wstring(severity));
        }
        if (!processName.empty()) {
            LogMessage(L"    └─ 发起进程: " + processName + L" (PID: " + std::to_wstring(driverEvent.ProcessId) + L")");
        }
        if (!targetPath.empty()) {
            LogMessage(L"    └─ 受保护文件: " + targetPath);
        }
    }
    else if (driverEvent.EventType == DRIVER_EVENT_TYPE_RESPONSE_ACTION) {
        LogMessage(responseSucceeded
            ? L"[+] 驱动响应动作执行成功。"
            : L"[!] 驱动响应动作执行失败。");
        LogMessage(L"    └─ 响应动作: " + responseAction);
        LogMessage(L"    └─ 目标 PID: " + std::to_wstring(driverEvent.ProcessId));
        if (!processName.empty()) {
            LogMessage(L"    └─ 目标进程: " + processName);
        }
        LogMessage(L"    └─ NTSTATUS: " + responseStatusText);
    }
    else {
        LogMessage(L"[!] 收到未知驱动事件类型: " + std::to_wstring(driverEvent.EventType));
    }

    json driverEventJson = BuildBaseJsonEvent(
        isObservedProcessCreate ? "observed_process_create" :
        (isBlockedFileOperation ? "blocked_file_operation" : "driver_event"),
        (driverEvent.EventType == DRIVER_EVENT_TYPE_RESPONSE_ACTION && responseSucceeded) ? "info" :
        (isObservedProcessCreate ? "info" : "warn"));
    driverEventJson["driver_event_type"] = driverEvent.EventType;
    driverEventJson["driver_event_name"] = WStringToUtf8(driverEventTypeName);
    driverEventJson["process_id"] = driverEvent.ProcessId;
    driverEventJson["severity"] = severity;
    if (driverEvent.EventType == DRIVER_EVENT_TYPE_RESPONSE_ACTION) {
        driverEventJson["response_action"] = WStringToUtf8(responseAction);
        driverEventJson["response_status"] = WStringToUtf8(responseStatusText);
        driverEventJson["response_success"] = responseSucceeded;
    }
    else if (isObservedProcessCreate) {
        driverEventJson["parent_process_id"] = parentProcessId;
        if (!parentProcessName.empty()) {
            driverEventJson["parent_process_name"] = WStringToUtf8(parentProcessName);
        }
        if (!targetPath.empty()) {
            driverEventJson["image_path"] = WStringToUtf8(targetPath);
        }
        if (!commandLine.empty()) {
            driverEventJson["command_line"] = WStringToUtf8(commandLine);
        }
    }
    else if (isRegistryDriverEvent) {
        driverEventJson["registry_operation"] = WStringToUtf8(registryOperation);
    }
    else if (isBlockedFileOperation) {
        driverEventJson["protected_file_operation"] = true;
        if (isDriverSelfProtection) {
            driverEventJson["self_protection"] = true;
            driverEventJson["protection_scope"] = "driver_self_protection";
        }
    }
    if (!processName.empty()) {
        driverEventJson["process_name"] = WStringToUtf8(processName);
    }
    if (!ruleId.empty()) {
        driverEventJson["rule_id"] = WStringToUtf8(ruleId);
    }
    if (!threatDesc.empty()) {
        driverEventJson["threat_desc"] = WStringToUtf8(threatDesc);
    }
    if (!targetPath.empty() && !isObservedProcessCreate) {
        driverEventJson["target_path"] = WStringToUtf8(targetPath);
    }
    if (!infoClass.empty()) {
        driverEventJson["info_class"] = WStringToUtf8(infoClass);
    }
    if (!valueName.empty()) {
        driverEventJson["value_name"] = WStringToUtf8(valueName);
    }
    if (!valueData.empty()) {
        if (driverEvent.RegistryOperation == REGISTRY_OPERATION_RENAME_KEY) {
            driverEventJson["new_name"] = WStringToUtf8(valueData);
        }
        else {
            driverEventJson["value_data"] = WStringToUtf8(valueData);
        }
    }
    EmitJsonEvent(driverEventJson);

    MaybeAutoTerminateProcessForDriverEvent(
        driverEvent,
        processName,
        ruleId,
        threatDesc,
        severity,
        targetPath,
        registryOperation);
}
void DriverEventMonitorThread() {
    DWORD reconnectBackoffMs = kDriverEventBackoffMinMs;

    while (!IsShutdownRequested()) {
        HANDLE hDriverDevice = OpenDriverDeviceOverlapped();
        if (hDriverDevice == INVALID_HANDLE_VALUE) {
            LogMessage(L"[-] 驱动遥测通道连接失败，" + std::to_wstring(reconnectBackoffMs) + L"ms 后重试。");
            if (WaitForShutdown(reconnectBackoffMs)) {
                break;
            }
            reconnectBackoffMs =
                (reconnectBackoffMs >= (kDriverEventBackoffMaxMs / 2))
                ? kDriverEventBackoffMaxMs
                : (reconnectBackoffMs * 2);
            continue;
        }

        reconnectBackoffMs = kDriverEventBackoffMinMs;
        TrackDeviceHandle(g_DriverEventDeviceHandle, hDriverDevice);
        LogMessage(L"[+] 驱动防御遥测通道已开启（IOCP 模式），正在监听底层拦截事件...");

        HANDLE hIocp = CreateIoCompletionPort(hDriverDevice, NULL, 0, 1);
        if (hIocp == NULL) {
            DWORD err = GetLastError();
            LogMessage(L"[!] 驱动遥测通道 IOCP 初始化失败，错误码: " + std::to_wstring(err));
            CloseTrackedHandle(hDriverDevice, g_DriverEventDeviceHandle);
            if (WaitForShutdown(reconnectBackoffMs)) {
                break;
            }
            reconnectBackoffMs =
                (reconnectBackoffMs >= (kDriverEventBackoffMaxMs / 2))
                ? kDriverEventBackoffMaxMs
                : (reconnectBackoffMs * 2);
            continue;
        }

        DriverEventAsyncContext asyncContext = {};
        if (!PostDriverEventReceive(hDriverDevice, asyncContext)) {
            DWORD err = GetLastError();
            if (!IsShutdownRequested() && err != ERROR_OPERATION_ABORTED && err != ERROR_INVALID_HANDLE) {
                LogMessage(L"[!] 驱动遥测异步请求投递失败，错误码: " + std::to_wstring(err));
            }
            CancelIoEx(hDriverDevice, NULL);
            CloseHandle(hIocp);
            CloseTrackedHandle(hDriverDevice, g_DriverEventDeviceHandle);
            if (WaitForShutdown(reconnectBackoffMs)) {
                break;
            }
            reconnectBackoffMs =
                (reconnectBackoffMs >= (kDriverEventBackoffMaxMs / 2))
                ? kDriverEventBackoffMaxMs
                : (reconnectBackoffMs * 2);
            continue;
        }

        while (!IsShutdownRequested()) {
            DWORD transferred = 0;
            ULONG_PTR completionKey = 0;
            LPOVERLAPPED overlapped = NULL;
            BOOL completed = GetQueuedCompletionStatus(
                hIocp,
                &transferred,
                &completionKey,
                &overlapped,
                1000);
            UNREFERENCED_PARAMETER(completionKey);

            if (overlapped == NULL) {
                if (!completed && GetLastError() == WAIT_TIMEOUT) {
                    continue;
                }

                DWORD err = GetLastError();
                if (!IsShutdownRequested() && err != ERROR_OPERATION_ABORTED && err != ERROR_INVALID_HANDLE) {
                    LogMessage(L"[!] 驱动遥测 IOCP 等待失败，错误码: " + std::to_wstring(err));
                }
                break;
            }

            if (!completed) {
                DWORD err = GetLastError();
                if (!IsShutdownRequested() && err != ERROR_OPERATION_ABORTED && err != ERROR_INVALID_HANDLE) {
                    LogMessage(L"[!] 驱动遥测异步请求失败，错误码: " + std::to_wstring(err));
                }
                break;
            }

            if (transferred == sizeof(DRIVER_EVENT)) {
                HandleDriverEventPayload(asyncContext.driverEvent);
            }
            else if (!IsShutdownRequested()) {
                LogMessage(L"[!] 驱动遥测收到异常长度数据，bytes=" + std::to_wstring(transferred));
            }

            if (!PostDriverEventReceive(hDriverDevice, asyncContext)) {
                DWORD err = GetLastError();
                if (!IsShutdownRequested() && err != ERROR_OPERATION_ABORTED && err != ERROR_INVALID_HANDLE) {
                    LogMessage(L"[!] 驱动遥测异步请求重投递失败，错误码: " + std::to_wstring(err));
                }
                break;
            }
        }

        CancelIoEx(hDriverDevice, NULL);
        CloseHandle(hIocp);
        CloseTrackedHandle(hDriverDevice, g_DriverEventDeviceHandle);
    }
}

static int RunProtectionEngine(bool serviceMode) {
    if (!serviceMode && !IsRunAsAdmin()) {
        std::wcout << L"[-] 致命错误：必须以【管理员身份】运行此防御系统！" << std::endl;
        std::wcout << L"    请右键点击 exe，选择“以管理员身份运行”。" << std::endl;
        system("pause");
        return 1;
    }

    if (!EnsureRuntimeEvents()) {
        std::wcerr << L"[-] 致命错误：初始化退出同步对象失败 (错误码: " << GetLastError() << L")" << std::endl;
        CleanupRuntimeEvents();
        if (!serviceMode) {
            system("pause");
        }
        return 1;
    }

    if (!serviceMode) {
        if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
            std::wcerr << L"[!] 警告：注册控制台退出处理器失败 (错误码: " << GetLastError() << L")，关闭窗口时可能无法自动卸载驱动。" << std::endl;
        }

        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        if (GetConsoleMode(hStdin, &mode)) {
            mode &= ~ENABLE_QUICK_EDIT_MODE;
            mode &= ~ENABLE_INSERT_MODE;
            SetConsoleMode(hStdin, mode);
        }
    }

    HANDLE hDevice = INVALID_HANDLE_VALUE;
    std::thread heartbeatThread;
    std::thread processThread;
    std::thread driverThread;
    std::thread ruleReloadThread;
    int exitCode = 0;
    std::wstring rulesPath = ResolveRulesFilePath();

    LogMessage(serviceMode ? L"[*] HostGuard 服务模式启动中..." : L"[*] 正在初始化 HostGuard 终端防御系统...");
    LogMessage(L"[*] 当前工作目录: " + g_ExeDirectory);
    LogMessage(L"[*] 探测到操作系统架构: " + std::wstring(Is64BitOS() ? L"x64" : L"x86"));
    LogMessage(L"[*] 当前规则文件路径: " + rulesPath);

    if (!ReloadRulesFromDisk(rulesPath, false)) {
        LogMessage(L"[!] 警告: 未能成功加载 JSON 规则库或文件不存在，将以空规则模式运行。");
    }

    std::wstring driverPath = FindLocalDriverPath();
    if (!driverPath.empty()) {
        LogMessage(L"[*] 当前目录发现驱动文件: " + driverPath);
        LogMessage(L"[*] 正在向内核注册 PebMonitor 服务...");
        if (LoadKernelDriver(driverPath, kDriverServiceName)) {
            LogMessage(L"[+] 内核驱动加载成功，雷达已上线。");
        }
        else {
            LogMessage(L"[!] 驱动加载尝试失败，将继续尝试连接已加载的驱动设备。");
        }
    }
    else {
        LogMessage(L"[!] 当前目录未找到 PebMonitor.sys 或 DriverModule.sys，跳过驱动加载步骤。");
    }

    hDevice = OpenDriverDevice();
    if (hDevice == INVALID_HANDLE_VALUE) {
        LogMessage(L"[!] 无法连接驱动通信端口。请确认驱动已加载，或将 PebMonitor.sys / DriverModule.sys 放在当前目录后重试。");
        exitCode = 1;
        goto Cleanup;
    }
    TrackDeviceHandle(g_MainDeviceHandle, hDevice);

    if (!ApplyKernelRules(hDevice)) {
        LogMessage(L"[!] 警告：初始内核规则同步未完全成功，程序将继续运行并在后续重连时重试。");
    }

    heartbeatThread = std::thread(HeartbeatMonitorThread);
    processThread = std::thread(ProcessVerdictMonitorThread);
    driverThread = std::thread(DriverEventMonitorThread);
    ruleReloadThread = std::thread(RulesHotReloadThread, rulesPath);

    LogMessage(L"[+] HostGuard 主引擎启动完毕，进程裁决与驱动遥测管线已启动；当前仅保留进程与注册表防护。");

    while (!WaitForShutdown(1000)) {
    }

Cleanup:
    RequestShutdown();
    CloseTrackedHandle(hDevice, g_MainDeviceHandle);

    if (heartbeatThread.joinable()) {
        heartbeatThread.join();
    }
    if (processThread.joinable()) {
        processThread.join();
    }
    if (ruleReloadThread.joinable()) {
        ruleReloadThread.join();
    }
    if (driverThread.joinable()) {
        driverThread.join();
    }

    LogMessage(L"[*] 正在停止并卸载 PebMonitor 驱动服务...");
    if (UnloadKernelDriver(kDriverServiceName)) {
        LogMessage(L"[+] PebMonitor 驱动已停止并卸载。");
    }
    else {
        LogMessage(L"[!] PebMonitor 驱动停止或卸载失败，请检查服务状态。");
        if (exitCode == 0) {
            exitCode = 1;
        }
    }

    if (g_ShutdownCompleteEvent != NULL) {
        SetEvent(g_ShutdownCompleteEvent);
    }
    if (!serviceMode) {
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    }

    CleanupRuntimeEvents();
    return exitCode;
}

static VOID WINAPI HostGuardServiceMain(DWORD argc, LPWSTR* argv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_IsServiceMode = true;
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

    g_ServiceStatusHandle = RegisterServiceCtrlHandlerExW(
        kHostGuardServiceName,
        ServiceControlHandlerEx,
        NULL);
    if (g_ServiceStatusHandle == NULL) {
        g_IsServiceMode = false;
        return;
    }

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 15000);
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    int exitCode = RunProtectionEngine(true);
    ReportServiceStatus(SERVICE_STOPPED, exitCode == 0 ? NO_ERROR : static_cast<DWORD>(exitCode), 0);

    g_ServiceStatusHandle = NULL;
    g_IsServiceMode = false;
}

static bool TryRunAsService(int& outExitCode) {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(kHostGuardServiceName), HostGuardServiceMain },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcherW(serviceTable)) {
        outExitCode = 0;
        return true;
    }

    DWORD err = GetLastError();
    if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
        return false;
    }

    std::wcerr << L"[-] 错误：连接服务控制管理器失败 (错误码: " << err << L")" << std::endl;
    outExitCode = 1;
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    setlocale(LC_ALL, "");

    g_ExeDirectory = GetExeDirectory();
    std::wstring rulesPath = ResolveRulesFilePath();

    if (argc > 1) {
        if (_wcsicmp(argv[1], L"install") == 0) {
            return RunInstallServiceCommand();
        }

        if (_wcsicmp(argv[1], L"start") == 0) {
            return RunStartServiceCommand();
        }

        if (_wcsicmp(argv[1], L"stop") == 0) {
            return RunStopServiceCommand();
        }

        if (_wcsicmp(argv[1], L"uninstall") == 0 || _wcsicmp(argv[1], L"remove") == 0) {
            return RunUninstallServiceCommand();
        }

        if (_wcsicmp(argv[1], L"status-json") == 0) {
            return RunStatusCommand(rulesPath, true);
        }

        if (_wcsicmp(argv[1], L"status") == 0 || _wcsicmp(argv[1], L"--status") == 0) {
            bool jsonOutput = (argc > 2 && _wcsicmp(argv[2], L"--json") == 0);
            return RunStatusCommand(rulesPath, jsonOutput);
        }

        if ((_wcsicmp(argv[1], L"terminate") == 0 || _wcsicmp(argv[1], L"kill") == 0) && argc > 2) {
            return RunTerminateProcessCommand(argv[2]);
        }

        if (_wcsicmp(argv[1], L"terminate") == 0 || _wcsicmp(argv[1], L"kill") == 0) {
            std::wcerr << L"[-] 错误：缺少 PID 参数，例如：HostGuard.exe terminate 1234" << std::endl;
            return 1;
        }

        if (_wcsicmp(argv[1], L"help") == 0 || _wcsicmp(argv[1], L"--help") == 0 || _wcsicmp(argv[1], L"/?") == 0) {
            std::wcout << L"Usage:" << std::endl;
            std::wcout << L"  HostGuard.exe              启动实时防护或由 SCM 拉起服务" << std::endl;
            std::wcout << L"  HostGuard.exe install      安装 HostGuard 服务" << std::endl;
            std::wcout << L"  HostGuard.exe start        启动 HostGuard 服务" << std::endl;
            std::wcout << L"  HostGuard.exe stop         停止 HostGuard 服务" << std::endl;
            std::wcout << L"  HostGuard.exe uninstall    卸载 HostGuard 服务" << std::endl;
            std::wcout << L"  HostGuard.exe status       查看规则和驱动状态" << std::endl;
            std::wcout << L"  HostGuard.exe status --json 输出机器可解析的状态 JSON" << std::endl;
            std::wcout << L"  HostGuard.exe status-json  输出机器可解析的状态 JSON" << std::endl;
            std::wcout << L"  HostGuard.exe terminate PID 通过驱动强制终止目标进程" << std::endl;
            return 0;
        }
    }

    int serviceExitCode = 0;
    if (TryRunAsService(serviceExitCode)) {
        return serviceExitCode;
    }

    return RunProtectionEngine(false);
}




