#include "DriverUtils.h"
#include <iostream>
#include <setupapi.h>
#include "Shared.h"

#pragma comment(lib, "Setupapi.lib")

namespace {
    const wchar_t kFilterLoadOrderGroup[] = L"FSFilter Activity Monitor";
    const wchar_t kFilterAltitude[] = L"370050";
    const wchar_t kFilterDependencies[] = L"FltMgr\0";
    const wchar_t* const kDriverInfCandidateNames[] = {
        L"DriverModule.inf",
        L"PebMonitor.inf"
    };

    bool QueryServiceStatus(SC_HANDLE hService, SERVICE_STATUS_PROCESS& status) {
        DWORD bytesNeeded = 0;
        ZeroMemory(&status, sizeof(status));
        return QueryServiceStatusEx(
            hService,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytesNeeded) == TRUE;
    }

    bool WaitForServiceState(SC_HANDLE hService, DWORD expectedState, DWORD timeoutMs) {
        DWORD waitedMs = 0;
        while (waitedMs < timeoutMs) {
            SERVICE_STATUS_PROCESS status;
            if (!QueryServiceStatus(hService, status)) {
                return false;
            }
            if (status.dwCurrentState == expectedState) {
                return true;
            }
            Sleep(200);
            waitedMs += 200;
        }

        SERVICE_STATUS_PROCESS status;
        return QueryServiceStatus(hService, status) && status.dwCurrentState == expectedState;
    }

    std::wstring QueryServiceBinaryPath(SC_HANDLE hService) {
        DWORD bytesNeeded = 0;
        QueryServiceConfigW(hService, NULL, 0, &bytesNeeded);
        if (bytesNeeded == 0) {
            return L"";
        }

        std::vector<BYTE> buffer(bytesNeeded, 0);
        QUERY_SERVICE_CONFIGW* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (!QueryServiceConfigW(hService, config, bytesNeeded, &bytesNeeded) || config->lpBinaryPathName == NULL) {
            return L"";
        }

        return std::wstring(config->lpBinaryPathName);
    }

    std::wstring ResolveServiceBinaryPath(const std::wstring& serviceBinaryPath) {
        if (serviceBinaryPath.empty()) {
            return L"";
        }

        std::wstring normalized = serviceBinaryPath;
        if (normalized.size() >= 2 && normalized.front() == L'"' && normalized.back() == L'"') {
            normalized = normalized.substr(1, normalized.size() - 2);
        }

        if (normalized.find(L':') != std::wstring::npos ||
            normalized.rfind(L"\\\\", 0) == 0) {
            return normalized;
        }

        wchar_t windowsDirectory[MAX_PATH] = {};
        UINT length = GetWindowsDirectoryW(windowsDirectory, RTL_NUMBER_OF(windowsDirectory));
        if (length == 0 || length >= RTL_NUMBER_OF(windowsDirectory)) {
            return normalized;
        }

        const std::wstring windowsRoot = windowsDirectory;
        if (_wcsnicmp(normalized.c_str(), L"system32\\", 9) == 0) {
            return windowsRoot + L"\\" + normalized;
        }

        if (_wcsnicmp(normalized.c_str(), L"\\SystemRoot\\", 12) == 0) {
            return windowsRoot + normalized.substr(11);
        }

        return normalized;
    }

    void LogServiceBinaryPathState(const std::wstring& serviceName, SC_HANDLE hService) {
        const std::wstring serviceBinaryPath = QueryServiceBinaryPath(hService);
        if (serviceBinaryPath.empty()) {
            return;
        }

        std::wcout << L"[*] 服务配置路径(" << serviceName << L"): " << serviceBinaryPath << std::endl;

        const std::wstring resolvedPath = ResolveServiceBinaryPath(serviceBinaryPath);
        if (resolvedPath.empty()) {
            return;
        }

        const DWORD attributes = GetFileAttributesW(resolvedPath.c_str());
        const bool fileExists =
            (attributes != INVALID_FILE_ATTRIBUTES) && ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0);

        std::wcout << L"[*] 解析后的文件路径(" << serviceName << L"): " << resolvedPath
                   << L" [" << (fileExists ? L"exists" : L"missing") << L"]"
                   << std::endl;
    }

    bool StopServiceIfRunning(SC_HANDLE hService) {
        SERVICE_STATUS_PROCESS status;
        if (!QueryServiceStatus(hService, status)) {
            std::wcerr << L"[-] 错误：查询驱动服务状态失败 (错误码: " << GetLastError() << L")" << std::endl;
            return false;
        }

        if (status.dwCurrentState == SERVICE_STOPPED) {
            return true;
        }

        if (status.dwCurrentState == SERVICE_STOP_PENDING) {
            return WaitForServiceState(hService, SERVICE_STOPPED, 10000);
        }

        SERVICE_STATUS serviceStatus = {};
        if (!ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus)) {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_NOT_ACTIVE) {
                return true;
            }
            std::wcerr << L"[-] 错误：停止旧驱动服务失败 (错误码: " << err << L")" << std::endl;
            return false;
        }

        if (!WaitForServiceState(hService, SERVICE_STOPPED, 10000)) {
            std::wcerr << L"[-] 错误：等待驱动服务停止超时。" << std::endl;
            return false;
        }
        return true;
    }

    bool ConfigureMinifilterServiceInstance(const std::wstring& serviceName) {
        HKEY serviceKey = NULL;
        const std::wstring serviceRegistryPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
        LONG result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            serviceRegistryPath.c_str(),
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
            NULL,
            &serviceKey,
            NULL);
        if (result != ERROR_SUCCESS) {
            std::wcerr << L"[-] 错误：创建驱动服务注册表项失败 (错误码: " << result << L")" << std::endl;
            return false;
        }

        HKEY instancesKey = NULL;
        result = RegCreateKeyExW(
            serviceKey,
            L"Instances",
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
            NULL,
            &instancesKey,
            NULL);
        if (result != ERROR_SUCCESS) {
            RegCloseKey(serviceKey);
            std::wcerr << L"[-] 错误：创建 minifilter Instances 注册表项失败 (错误码: " << result << L")" << std::endl;
            return false;
        }

        const std::wstring instanceName = serviceName + L" Instance";
        result = RegSetValueExW(
            instancesKey,
            L"DefaultInstance",
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(instanceName.c_str()),
            static_cast<DWORD>((instanceName.size() + 1) * sizeof(wchar_t)));
        if (result == ERROR_SUCCESS) {
            HKEY instanceKey = NULL;
            result = RegCreateKeyExW(
                instancesKey,
                instanceName.c_str(),
                0,
                NULL,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                NULL,
                &instanceKey,
                NULL);
            if (result == ERROR_SUCCESS) {
                DWORD flags = 0;
                RegSetValueExW(
                    instanceKey,
                    L"Flags",
                    0,
                    REG_DWORD,
                    reinterpret_cast<const BYTE*>(&flags),
                    sizeof(flags));
                RegSetValueExW(
                    instanceKey,
                    L"Altitude",
                    0,
                    REG_SZ,
                    reinterpret_cast<const BYTE*>(kFilterAltitude),
                    static_cast<DWORD>((wcslen(kFilterAltitude) + 1) * sizeof(wchar_t)));
                RegCloseKey(instanceKey);
            }
        }

        RegCloseKey(instancesKey);
        RegCloseKey(serviceKey);

        if (result != ERROR_SUCCESS) {
            std::wcerr << L"[-] 错误：写入 minifilter 实例配置失败 (错误码: " << result << L")" << std::endl;
            return false;
        }

        return true;
    }

    std::wstring GetDirectoryPath(const std::wstring& path) {
        const size_t separator = path.find_last_of(L"\\/");
        if (separator == std::wstring::npos) {
            return L"";
        }

        return path.substr(0, separator + 1);
    }

    std::wstring GetCurrentModuleDirectory() {
        wchar_t modulePath[MAX_PATH] = {};
        if (GetModuleFileNameW(NULL, modulePath, RTL_NUMBER_OF(modulePath)) == 0) {
            return L"";
        }

        return GetDirectoryPath(modulePath);
    }

    std::wstring QuoteCommandArgument(const std::wstring& value) {
        if (value.find_first_of(L" \t\"") == std::wstring::npos) {
            return value;
        }

        std::wstring quoted = L"\"";
        quoted += value;
        quoted += L"\"";
        return quoted;
    }

    std::wstring FindDriverInfPathInDirectory(const std::wstring& directoryPath) {
        if (directoryPath.empty()) {
            return L"";
        }

        for (const wchar_t* candidateName : kDriverInfCandidateNames) {
            const std::wstring candidatePath = directoryPath + candidateName;
            if (IsFileExists(candidatePath)) {
                return candidatePath;
            }
        }

        return L"";
    }

    std::wstring FindSiblingDriverInfPath(const std::wstring& driverPath) {
        if (driverPath.empty()) {
            return L"";
        }

        return FindDriverInfPathInDirectory(GetDirectoryPath(driverPath));
    }

    bool InvokeInfSection(
        const std::wstring& infPath,
        const std::wstring& sectionName) {
        if (!IsFileExists(infPath)) {
            return false;
        }

        std::wstring commandLine = sectionName;
        commandLine += L" 132 ";
        commandLine += QuoteCommandArgument(infPath);

        InstallHinfSectionW(NULL, NULL, commandLine.c_str(), 0);
        return true;
    }
}

bool IsRunAsAdmin() {
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
        CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin);
        FreeSid(pAdministratorsGroup);
    }
    return fIsRunAsAdmin == TRUE;
}

bool IsFileExists(const std::wstring& filePath) {
    DWORD dwAttrib = GetFileAttributesW(filePath.c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool QueryWin32ServiceState(
    const std::wstring& serviceName,
    DWORD& outState,
    bool& outExists) {
    outState = SERVICE_STOPPED;
    outExists = false;

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        std::wcerr << L"[-] 错误：无法打开服务控制管理器 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCManager);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            return true;
        }

        std::wcerr << L"[-] 错误：查询服务状态失败 (错误码: " << err << L")" << std::endl;
        return false;
    }

    SERVICE_STATUS_PROCESS status = {};
    outExists = true;
    bool success = QueryServiceStatus(hService, status);
    if (success) {
        outState = status.dwCurrentState;
    }
    else {
        std::wcerr << L"[-] 错误：读取服务状态失败 (错误码: " << GetLastError() << L")" << std::endl;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

bool InstallWin32Service(
    const std::wstring& serviceName,
    const std::wstring& displayName,
    const std::wstring& binaryPath,
    DWORD startType) {
    if (!IsRunAsAdmin()) {
        std::wcerr << L"[-] 错误：安装服务需要管理员权限！" << std::endl;
        return false;
    }

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        std::wcerr << L"[-] 错误：无法打开服务控制管理器 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    SC_HANDLE hService = CreateServiceW(
        hSCManager,
        serviceName.c_str(),
        displayName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        startType,
        SERVICE_ERROR_NORMAL,
        binaryPath.c_str(),
        NULL,
        NULL,
        NULL,
        L"LocalSystem",
        NULL);

    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
            if (!hService) {
                std::wcerr << L"[-] 错误：服务已存在，但重新打开失败 (错误码: " << GetLastError() << L")" << std::endl;
                CloseServiceHandle(hSCManager);
                return false;
            }

            if (!ChangeServiceConfigW(
                hService,
                SERVICE_NO_CHANGE,
                startType,
                SERVICE_NO_CHANGE,
                binaryPath.c_str(),
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                displayName.c_str())) {
                std::wcerr << L"[-] 错误：更新已有服务配置失败 (错误码: " << GetLastError() << L")" << std::endl;
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return false;
            }
        }
        else {
            std::wcerr << L"[-] 错误：创建服务失败 (错误码: " << err << L")" << std::endl;
            CloseServiceHandle(hSCManager);
            return false;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

bool StartWin32Service(const std::wstring& serviceName) {
    if (!IsRunAsAdmin()) {
        std::wcerr << L"[-] 错误：启动服务需要管理员权限！" << std::endl;
        return false;
    }

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        std::wcerr << L"[-] 错误：无法打开服务控制管理器 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        serviceName.c_str(),
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!hService) {
        std::wcerr << L"[-] 错误：打开服务失败 (错误码: " << GetLastError() << L")" << std::endl;
        CloseServiceHandle(hSCManager);
        return false;
    }

    LogServiceBinaryPathState(serviceName, hService);

    bool success = true;
    if (!StartServiceW(hService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            std::wcerr << L"[-] 错误：启动服务失败 (错误码: " << err << L")" << std::endl;
            LogServiceBinaryPathState(serviceName, hService);
            success = false;
        }
    }

    if (success && !WaitForServiceState(hService, SERVICE_RUNNING, 15000)) {
        std::wcerr << L"[-] 错误：等待服务进入运行状态超时。" << std::endl;
        success = false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

bool StopWin32Service(const std::wstring& serviceName) {
    if (!IsRunAsAdmin()) {
        std::wcerr << L"[-] 错误：停止服务需要管理员权限！" << std::endl;
        return false;
    }

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        std::wcerr << L"[-] 错误：无法打开服务控制管理器 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCManager);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            return true;
        }

        std::wcerr << L"[-] 错误：打开服务失败 (错误码: " << err << L")" << std::endl;
        return false;
    }

    bool success = StopServiceIfRunning(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

bool RemoveWin32Service(const std::wstring& serviceName) {
    if (!IsRunAsAdmin()) {
        std::wcerr << L"[-] 错误：卸载服务需要管理员权限！" << std::endl;
        return false;
    }

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        std::wcerr << L"[-] 错误：无法打开服务控制管理器 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCManager);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            return true;
        }

        std::wcerr << L"[-] 错误：打开服务失败 (错误码: " << err << L")" << std::endl;
        return false;
    }

    bool success = StopServiceIfRunning(hService);
    if (success && !DeleteService(hService)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_MARKED_FOR_DELETE && err != ERROR_SERVICE_DOES_NOT_EXIST) {
            std::wcerr << L"[-] 错误：删除服务失败 (错误码: " << err << L")" << std::endl;
            success = false;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

bool QueryKernelDriverServiceState(
    const std::wstring& serviceName,
    DWORD& outState,
    bool& outExists) {
    return QueryWin32ServiceState(serviceName, outState, outExists);
}

static bool InstallKernelDriverViaInf(
    const std::wstring& infPath,
    const std::wstring& serviceName) {
    DWORD serviceState = SERVICE_STOPPED;
    bool serviceExists = false;
    if (QueryKernelDriverServiceState(serviceName, serviceState, serviceExists) && serviceExists) {
        if (!StopWin32Service(serviceName)) {
            return false;
        }
    }

    if (!InvokeInfSection(infPath, L"DefaultInstall")) {
        return false;
    }

    DWORD installedState = SERVICE_STOPPED;
    bool installedExists = false;
    if (!QueryKernelDriverServiceState(serviceName, installedState, installedExists) || !installedExists) {
        std::wcerr << L"[-] 错误：执行 INF 安装后未发现驱动服务。INF: " << infPath << std::endl;
        return false;
    }

    return true;
}

static bool UninstallKernelDriverViaInf(
    const std::wstring& infPath,
    const std::wstring& serviceName) {
    if (!StopWin32Service(serviceName)) {
        return false;
    }

    if (!InvokeInfSection(infPath, L"DefaultUninstall")) {
        return false;
    }

    DWORD serviceState = SERVICE_STOPPED;
    bool serviceExists = false;
    if (!QueryKernelDriverServiceState(serviceName, serviceState, serviceExists)) {
        return false;
    }

    return !serviceExists;
}

bool LoadKernelDriver(const std::wstring& driverPath, const std::wstring& serviceName) {
    if (!IsRunAsAdmin()) {
        std::wcerr << L"[-] 错误：加载驱动需要管理员权限！" << std::endl;
        return false;
    }

    if (!IsFileExists(driverPath)) {
        std::wcerr << L"[-] 错误：驱动文件不存在，无法注册服务！路径: " << driverPath << std::endl;
        return false;
    }

    const std::wstring infPath = FindSiblingDriverInfPath(driverPath);
    if (!infPath.empty()) {
        if (InstallKernelDriverViaInf(infPath, serviceName)) {
            if (!StartWin32Service(serviceName)) {
                std::wcerr << L"[-] 错误：INF 安装完成，但驱动服务启动失败。" << std::endl;
                return false;
            }

            return true;
        }

        std::wcerr << L"[!] 警告：标准 INF 安装失败，回退到旧版服务注册路径。INF: " << infPath << std::endl;
    }

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        std::wcerr << L"[-] 错误：无法打开服务控制管理器 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    bool createdService = false;
    SC_HANDLE hService = CreateServiceW(hSCManager, serviceName.c_str(), serviceName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        driverPath.c_str(), kFilterLoadOrderGroup, NULL, kFilterDependencies, NULL, NULL);

    if (!hService) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            hService = OpenServiceW(hSCManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
            if (!hService) {
                std::wcerr << L"[-] 错误：服务已存在，但重新打开失败 (错误码: " << GetLastError() << L")" << std::endl;
                CloseServiceHandle(hSCManager);
                return false;
            }

            if (!ChangeServiceConfigW(
                hService,
                SERVICE_FILE_SYSTEM_DRIVER,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                driverPath.c_str(),
                kFilterLoadOrderGroup,
                NULL,
                kFilterDependencies,
                NULL,
                NULL,
                NULL)) {
                std::wcerr << L"[-] 错误：更新已有驱动服务路径失败 (错误码: " << GetLastError() << L")" << std::endl;
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return false;
            }

            if (!StopServiceIfRunning(hService)) {
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return false;
            }
        }
        else {
            std::wcerr << L"[-] 错误：创建服务失败 (错误码: " << GetLastError() << L")" << std::endl;
            CloseServiceHandle(hSCManager);
            return false;
        }
    }
    else {
        createdService = true;
    }

    if (!ConfigureMinifilterServiceInstance(serviceName)) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return false;
    }

    bool success = true;
    if (!StartServiceW(hService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            std::wcerr << L"[-] 错误：驱动服务启动失败 (错误码: " << err << L")" << std::endl;
            success = false;

            if (createdService) {
                DeleteService(hService);
            }
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

bool UnloadKernelDriver(const std::wstring& serviceName) {
    if (!IsRunAsAdmin()) {
        std::wcerr << L"[-] 错误：卸载驱动需要管理员权限！" << std::endl;
        return false;
    }

    const std::wstring infPath = FindDriverInfPathInDirectory(GetCurrentModuleDirectory());
    if (!infPath.empty()) {
        if (UninstallKernelDriverViaInf(infPath, serviceName)) {
            return true;
        }

        std::wcerr << L"[!] 警告：标准 INF 卸载失败，回退到旧版服务删除路径。INF: " << infPath << std::endl;
    }

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        std::wcerr << L"[-] 错误：无法打开服务控制管理器 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        serviceName.c_str(),
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!hService) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCManager);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            return true;
        }

        std::wcerr << L"[-] 错误：打开驱动服务失败 (错误码: " << err << L")" << std::endl;
        return false;
    }

    bool success = StopServiceIfRunning(hService);
    if (success && !DeleteService(hService)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_MARKED_FOR_DELETE && err != ERROR_SERVICE_DOES_NOT_EXIST) {
            std::wcerr << L"[-] 错误：删除驱动服务失败 (错误码: " << err << L")" << std::endl;
            success = false;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return success;
}

bool AddRegistryRule(HANDLE hDevice, const REGISTRY_RULE& inputRule) {
    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
        std::wcerr << L"[-] 错误：传入的驱动通信句柄无效！" << std::endl;
        return false;
    }

    REGISTRY_RULE rule = inputRule;
    rule.RuleId[MAX_RULE_ID_LENGTH - 1] = L'\0';
    rule.ProcessName[MAX_RULE_LENGTH - 1] = L'\0';
    rule.KeyPath[MAX_REG_PATH_LENGTH - 1] = L'\0';
    rule.InfoClass[MAX_RULE_LENGTH - 1] = L'\0';
    rule.ValueName[MAX_RULE_LENGTH - 1] = L'\0';
    rule.ValueData[MAX_RULE_LENGTH - 1] = L'\0';

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_ADD_REGISTRY_RULE,
        &rule,
        sizeof(REGISTRY_RULE),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {
        std::wcerr << L"[-] 错误：下发注册表规则失败，IOCTL 拒绝 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    return true;
}

static bool ReplaceRegistryRuleBatch(
    HANDLE hDevice,
    DWORD ioctlCode,
    const std::vector<REGISTRY_RULE>& inputRules,
    const wchar_t* errorPrefix,
    DWORD* outErrorCode) {
    if (outErrorCode != nullptr) {
        *outErrorCode = ERROR_SUCCESS;
    }

    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
        std::wcerr << L"[-] 错误：传入的驱动通信句柄无效！" << std::endl;
        if (outErrorCode != nullptr) {
            *outErrorCode = ERROR_INVALID_HANDLE;
        }
        return false;
    }

    const size_t ruleCount = inputRules.size();
    const size_t headerSize = FIELD_OFFSET(REGISTRY_RULE_BATCH_UPDATE, Rules);
    const size_t maxRuleCount = MAXDWORD / sizeof(REGISTRY_RULE);
    if (ruleCount > maxRuleCount || (headerSize + sizeof(REGISTRY_RULE) * ruleCount) > MAXDWORD) {
        std::wcerr << L"[-] 错误：注册表规则数量过大，无法进行批量同步。" << std::endl;
        if (outErrorCode != nullptr) {
            *outErrorCode = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    const DWORD requestSize = static_cast<DWORD>(headerSize + sizeof(REGISTRY_RULE) * ruleCount);
    std::vector<BYTE> requestBuffer(requestSize, 0);
    REGISTRY_RULE_BATCH_UPDATE* batchUpdate =
        reinterpret_cast<REGISTRY_RULE_BATCH_UPDATE*>(requestBuffer.data());
    batchUpdate->AbiVersion = PEBMONITOR_ABI_VERSION;
    batchUpdate->RuleCount = static_cast<ULONG>(ruleCount);

    for (size_t index = 0; index < ruleCount; ++index) {
        REGISTRY_RULE sanitizedRule = inputRules[index];
        sanitizedRule.RuleId[MAX_RULE_ID_LENGTH - 1] = L'\0';
        sanitizedRule.ProcessName[MAX_RULE_LENGTH - 1] = L'\0';
        sanitizedRule.KeyPath[MAX_REG_PATH_LENGTH - 1] = L'\0';
        sanitizedRule.InfoClass[MAX_RULE_LENGTH - 1] = L'\0';
        sanitizedRule.ValueName[MAX_RULE_LENGTH - 1] = L'\0';
        sanitizedRule.ValueData[MAX_RULE_LENGTH - 1] = L'\0';
        batchUpdate->Rules[index] = sanitizedRule;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice,
        ioctlCode,
        batchUpdate,
        requestSize,
        NULL,
        0,
        &bytesReturned,
        NULL);

    if (!result) {
        DWORD errorCode = GetLastError();
        if (outErrorCode != nullptr) {
            *outErrorCode = errorCode;
        }
        if (errorPrefix != nullptr &&
            errorPrefix[0] != L'\0' &&
            errorCode != ERROR_INVALID_FUNCTION &&
            errorCode != ERROR_NOT_SUPPORTED &&
            errorCode != ERROR_CALL_NOT_IMPLEMENTED) {
            std::wcerr << errorPrefix << L" (错误码: " << errorCode << L")" << std::endl;
        }
        return false;
    }

    return true;
}

bool ClearRegistryRules(HANDLE hDevice) {
    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
        std::wcerr << L"[-] 错误：传入的驱动通信句柄无效！" << std::endl;
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(hDevice, IOCTL_CLEAR_REGISTRY_RULES, NULL, 0, NULL, 0, &bytesReturned, NULL);

    if (!result) {
        std::wcerr << L"[-] 错误：清空注册表规则失败 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    return true;
}

bool AddRegistryAllowRule(HANDLE hDevice, const REGISTRY_RULE& inputRule) {
    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
        std::wcerr << L"[-] 错误：传入的驱动通信句柄无效！" << std::endl;
        return false;
    }

    REGISTRY_RULE rule = inputRule;
    rule.RuleId[MAX_RULE_ID_LENGTH - 1] = L'\0';
    rule.ProcessName[MAX_RULE_LENGTH - 1] = L'\0';
    rule.KeyPath[MAX_REG_PATH_LENGTH - 1] = L'\0';
    rule.InfoClass[MAX_RULE_LENGTH - 1] = L'\0';
    rule.ValueName[MAX_RULE_LENGTH - 1] = L'\0';
    rule.ValueData[MAX_RULE_LENGTH - 1] = L'\0';

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_ADD_REGISTRY_ALLOW_RULE,
        &rule,
        sizeof(REGISTRY_RULE),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {
        std::wcerr << L"[-] 错误：下发注册表白名单规则失败，IOCTL 拒绝 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    return true;
}

bool ClearRegistryAllowRules(HANDLE hDevice) {
    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
        std::wcerr << L"[-] 错误：传入的驱动通信句柄无效！" << std::endl;
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(hDevice, IOCTL_CLEAR_REGISTRY_ALLOW_RULES, NULL, 0, NULL, 0, &bytesReturned, NULL);

    if (!result) {
        std::wcerr << L"[-] 错误：清空注册表白名单规则失败 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    return true;
}

bool ReplaceRegistryRules(
    HANDLE hDevice,
    const std::vector<REGISTRY_RULE>& rules,
    DWORD* outErrorCode) {
    return ReplaceRegistryRuleBatch(
        hDevice,
        IOCTL_REPLACE_REGISTRY_RULES,
        rules,
        L"[-] 错误：批量下发注册表规则失败，IOCTL 拒绝",
        outErrorCode);
}

bool ReplaceRegistryAllowRules(
    HANDLE hDevice,
    const std::vector<REGISTRY_RULE>& rules,
    DWORD* outErrorCode) {
    return ReplaceRegistryRuleBatch(
        hDevice,
        IOCTL_REPLACE_REGISTRY_ALLOW_RULES,
        rules,
        L"[-] 错误：批量下发注册表白名单规则失败，IOCTL 拒绝",
        outErrorCode);
}

bool QueryDriverStatus(HANDLE hDevice, DRIVER_RUNTIME_STATUS& outStatus) {
    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
        std::wcerr << L"[-] 错误：传入的驱动通信句柄无效！" << std::endl;
        return false;
    }

    ZeroMemory(&outStatus, sizeof(outStatus));
    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_QUERY_DRIVER_STATUS,
        NULL,
        0,
        &outStatus,
        sizeof(outStatus),
        &bytesReturned,
        NULL);

    if (!result || bytesReturned != sizeof(outStatus)) {
        std::wcerr << L"[-] 错误：查询驱动状态失败 (错误码: " << GetLastError() << L")" << std::endl;
        ZeroMemory(&outStatus, sizeof(outStatus));
        return false;
    }

    if (!PEBMONITOR_ABI_IS_COMPAT(outStatus.AbiVersion)) {
        std::wcerr << L"[-] 错误：驱动状态 ABI 版本不兼容 (driver="
                   << outStatus.AbiVersion
                   << L", expected=" << PEBMONITOR_ABI_VERSION << L")"
                   << std::endl;
        ZeroMemory(&outStatus, sizeof(outStatus));
        SetLastError(ERROR_REVISION_MISMATCH);
        return false;
    }

    return true;
}

bool TerminateTargetProcess(HANDLE hDevice, DWORD processId, LONG exitStatus, DWORD* outErrorCode) {
    if (outErrorCode != nullptr) {
        *outErrorCode = ERROR_SUCCESS;
    }

    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
        std::wcerr << L"[-] 错误：传入的驱动通信句柄无效！" << std::endl;
        if (outErrorCode != nullptr) {
            *outErrorCode = ERROR_INVALID_HANDLE;
        }
        return false;
    }

    if (processId == 0) {
        std::wcerr << L"[-] 错误：目标 PID 无效。" << std::endl;
        if (outErrorCode != nullptr) {
            *outErrorCode = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    EDR_TERMINATE_PROCESS_REQUEST request = {};
    request.ProcessId = processId;
    request.ExitStatus = exitStatus;

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_EDR_TERMINATE_PROCESS,
        &request,
        sizeof(request),
        NULL,
        0,
        &bytesReturned,
        NULL);

    if (!result) {
        DWORD errorCode = GetLastError();
        if (outErrorCode != nullptr) {
            *outErrorCode = errorCode;
        }
        std::wcerr << L"[-] 错误：内核终止进程失败 (错误码: " << errorCode << L")" << std::endl;
        return false;
    }

    return true;
}

bool SetActiveDriverConfigInfo(
    HANDLE hDevice,
    const std::wstring& configVersion,
    const std::wstring& profileName,
    const std::wstring& generatedAt,
    ULONG processVerdictTimeoutMs,
    ULONG processVerdictFailMode,
    ULONG captureParentCommandLine) {
    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL) {
        std::wcerr << L"[-] 错误：传入的驱动通信句柄无效！" << std::endl;
        return false;
    }

    if (configVersion.length() >= MAX_RULE_LENGTH ||
        profileName.length() >= MAX_RULE_LENGTH ||
        generatedAt.length() >= MAX_RULE_LENGTH) {
        std::wcerr << L"[-] 错误：配置元数据过长，无法同步到驱动。" << std::endl;
        return false;
    }

    DRIVER_CONFIG_INFO configInfo = {};
    wcscpy_s(configInfo.ConfigVersion, MAX_RULE_LENGTH, configVersion.c_str());
    wcscpy_s(configInfo.ProfileName, MAX_RULE_LENGTH, profileName.c_str());
    wcscpy_s(configInfo.GeneratedAt, MAX_RULE_LENGTH, generatedAt.c_str());
    configInfo.ProcessVerdictTimeoutMs = processVerdictTimeoutMs;
    configInfo.ProcessVerdictFailMode = processVerdictFailMode;
    configInfo.CaptureParentCommandLine = captureParentCommandLine;




    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_SET_ACTIVE_CONFIG_INFO,
        &configInfo,
        sizeof(configInfo),
        NULL,
        0,
        &bytesReturned,
        NULL);

    if (!result) {
        std::wcerr << L"[-] 错误：同步驱动配置版本失败 (错误码: " << GetLastError() << L")" << std::endl;
        return false;
    }

    return true;
}

