#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include "Shared.h"

bool IsRunAsAdmin();
bool IsFileExists(const std::wstring& filePath);
bool QueryWin32ServiceState(const std::wstring& serviceName, DWORD& outState, bool& outExists);
bool QueryKernelDriverServiceState(const std::wstring& serviceName, DWORD& outState, bool& outExists);
bool InstallWin32Service(
    const std::wstring& serviceName,
    const std::wstring& displayName,
    const std::wstring& binaryPath,
    DWORD startType);
bool StartWin32Service(const std::wstring& serviceName);
bool StopWin32Service(const std::wstring& serviceName);
bool RemoveWin32Service(const std::wstring& serviceName);
bool LoadKernelDriver(const std::wstring& driverPath, const std::wstring& serviceName);
bool UnloadKernelDriver(const std::wstring& serviceName);

bool LoadDriverFromCurrentDirectory();
bool StopAndUnloadDriver();
bool IsDriverLoaded();
SC_HANDLE OpenHostGuardService(DWORD desiredAccess);
SC_HANDLE OpenDriverService(DWORD desiredAccess);
bool EnsureHostGuardServiceStopped();
bool EnsureDriverServiceStopped();
std::wstring QueryHostGuardBinaryPath();
std::wstring QueryDriverBinaryPath();
std::wstring QueryRuleFilePath();
std::wstring QueryProgramDataDirectory();
DWORD QueryServiceState(SC_HANDLE hService);
HANDLE OpenDriverDevice();

bool AddRegistryRule(HANDLE hDevice, const REGISTRY_RULE& rule);
bool ClearRegistryRules(HANDLE hDevice);
bool AddRegistryAllowRule(HANDLE hDevice, const REGISTRY_RULE& rule);
bool ClearRegistryAllowRules(HANDLE hDevice);
bool ReplaceRegistryRules(
    HANDLE hDevice,
    const std::vector<REGISTRY_RULE>& rules,
    DWORD* outErrorCode = nullptr);
bool ReplaceRegistryAllowRules(
    HANDLE hDevice,
    const std::vector<REGISTRY_RULE>& rules,
    DWORD* outErrorCode = nullptr);
bool QueryDriverStatus(HANDLE hDevice, DRIVER_RUNTIME_STATUS& outStatus);
bool TerminateTargetProcess(HANDLE hDevice, DWORD processId, LONG exitStatus, DWORD* outErrorCode = nullptr);
bool SetActiveDriverConfigInfo(
    HANDLE hDevice,
    const std::wstring& configVersion,
    const std::wstring& profileName,
    const std::wstring& generatedAt,
    ULONG processVerdictTimeoutMs,
    ULONG processVerdictFailMode,
    ULONG captureParentCommandLine);
