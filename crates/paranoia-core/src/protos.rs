//! Built-in prototypes for common Windows and C library APIs. Used to label
//! argument set-up instructions (`; lpFileName`) and to give pseudocode calls
//! the right number of arguments, as IDA does with its type libraries.

use std::collections::HashMap;

use crate::model::{Arch, Flow, Format, Instruction};
use crate::Binary;

pub struct Proto {
    pub ret: &'static str,
    pub params: &'static [&'static str],
}

macro_rules! protos {
    ($($name:literal => $ret:literal ( $($p:literal),* );)*) => {
        &[$(($name, Proto { ret: $ret, params: &[$($p),*] })),*]
    };
}

static PROTOS: &[(&str, Proto)] = protos! {
    // kernel32: files
    "CreateFileA" => "HANDLE"("LPCSTR lpFileName", "DWORD dwDesiredAccess", "DWORD dwShareMode", "LPSECURITY_ATTRIBUTES lpSecurityAttributes", "DWORD dwCreationDisposition", "DWORD dwFlagsAndAttributes", "HANDLE hTemplateFile");
    "CreateFileW" => "HANDLE"("LPCWSTR lpFileName", "DWORD dwDesiredAccess", "DWORD dwShareMode", "LPSECURITY_ATTRIBUTES lpSecurityAttributes", "DWORD dwCreationDisposition", "DWORD dwFlagsAndAttributes", "HANDLE hTemplateFile");
    "ReadFile" => "BOOL"("HANDLE hFile", "LPVOID lpBuffer", "DWORD nNumberOfBytesToRead", "LPDWORD lpNumberOfBytesRead", "LPOVERLAPPED lpOverlapped");
    "WriteFile" => "BOOL"("HANDLE hFile", "LPCVOID lpBuffer", "DWORD nNumberOfBytesToWrite", "LPDWORD lpNumberOfBytesWritten", "LPOVERLAPPED lpOverlapped");
    "CloseHandle" => "BOOL"("HANDLE hObject");
    "DeleteFileA" => "BOOL"("LPCSTR lpFileName");
    "DeleteFileW" => "BOOL"("LPCWSTR lpFileName");
    "CopyFileW" => "BOOL"("LPCWSTR lpExistingFileName", "LPCWSTR lpNewFileName", "BOOL bFailIfExists");
    "MoveFileExW" => "BOOL"("LPCWSTR lpExistingFileName", "LPCWSTR lpNewFileName", "DWORD dwFlags");
    "GetFileSize" => "DWORD"("HANDLE hFile", "LPDWORD lpFileSizeHigh");
    "GetFileSizeEx" => "BOOL"("HANDLE hFile", "PLARGE_INTEGER lpFileSize");
    "SetFilePointer" => "DWORD"("HANDLE hFile", "LONG lDistanceToMove", "PLONG lpDistanceToMoveHigh", "DWORD dwMoveMethod");
    "SetFilePointerEx" => "BOOL"("HANDLE hFile", "LARGE_INTEGER liDistanceToMove", "PLARGE_INTEGER lpNewFilePointer", "DWORD dwMoveMethod");
    "FindFirstFileW" => "HANDLE"("LPCWSTR lpFileName", "LPWIN32_FIND_DATAW lpFindFileData");
    "FindNextFileW" => "BOOL"("HANDLE hFindFile", "LPWIN32_FIND_DATAW lpFindFileData");
    "FindClose" => "BOOL"("HANDLE hFindFile");
    "CreateDirectoryW" => "BOOL"("LPCWSTR lpPathName", "LPSECURITY_ATTRIBUTES lpSecurityAttributes");
    "GetFullPathNameW" => "DWORD"("LPCWSTR lpFileName", "DWORD nBufferLength", "LPWSTR lpBuffer", "LPWSTR *lpFilePart");
    "GetTempPathW" => "DWORD"("DWORD nBufferLength", "LPWSTR lpBuffer");
    "GetFileAttributesW" => "DWORD"("LPCWSTR lpFileName");
    "CreateFileMappingW" => "HANDLE"("HANDLE hFile", "LPSECURITY_ATTRIBUTES lpFileMappingAttributes", "DWORD flProtect", "DWORD dwMaximumSizeHigh", "DWORD dwMaximumSizeLow", "LPCWSTR lpName");
    "MapViewOfFile" => "LPVOID"("HANDLE hFileMappingObject", "DWORD dwDesiredAccess", "DWORD dwFileOffsetHigh", "DWORD dwFileOffsetLow", "SIZE_T dwNumberOfBytesToMap");
    "UnmapViewOfFile" => "BOOL"("LPCVOID lpBaseAddress");
    "DeviceIoControl" => "BOOL"("HANDLE hDevice", "DWORD dwIoControlCode", "LPVOID lpInBuffer", "DWORD nInBufferSize", "LPVOID lpOutBuffer", "DWORD nOutBufferSize", "LPDWORD lpBytesReturned", "LPOVERLAPPED lpOverlapped");
    // kernel32: memory
    "VirtualAlloc" => "LPVOID"("LPVOID lpAddress", "SIZE_T dwSize", "DWORD flAllocationType", "DWORD flProtect");
    "VirtualAllocEx" => "LPVOID"("HANDLE hProcess", "LPVOID lpAddress", "SIZE_T dwSize", "DWORD flAllocationType", "DWORD flProtect");
    "VirtualFree" => "BOOL"("LPVOID lpAddress", "SIZE_T dwSize", "DWORD dwFreeType");
    "VirtualProtect" => "BOOL"("LPVOID lpAddress", "SIZE_T dwSize", "DWORD flNewProtect", "PDWORD lpflOldProtect");
    "VirtualProtectEx" => "BOOL"("HANDLE hProcess", "LPVOID lpAddress", "SIZE_T dwSize", "DWORD flNewProtect", "PDWORD lpflOldProtect");
    "VirtualQuery" => "SIZE_T"("LPCVOID lpAddress", "PMEMORY_BASIC_INFORMATION lpBuffer", "SIZE_T dwLength");
    "HeapAlloc" => "LPVOID"("HANDLE hHeap", "DWORD dwFlags", "SIZE_T dwBytes");
    "HeapFree" => "BOOL"("HANDLE hHeap", "DWORD dwFlags", "LPVOID lpMem");
    "HeapReAlloc" => "LPVOID"("HANDLE hHeap", "DWORD dwFlags", "LPVOID lpMem", "SIZE_T dwBytes");
    "GetProcessHeap" => "HANDLE"();
    "LocalAlloc" => "HLOCAL"("UINT uFlags", "SIZE_T uBytes");
    "LocalFree" => "HLOCAL"("HLOCAL hMem");
    "GlobalAlloc" => "HGLOBAL"("UINT uFlags", "SIZE_T dwBytes");
    "GlobalFree" => "HGLOBAL"("HGLOBAL hMem");
    // kernel32: processes, threads, modules
    "GetProcAddress" => "FARPROC"("HMODULE hModule", "LPCSTR lpProcName");
    "LoadLibraryA" => "HMODULE"("LPCSTR lpLibFileName");
    "LoadLibraryW" => "HMODULE"("LPCWSTR lpLibFileName");
    "LoadLibraryExA" => "HMODULE"("LPCSTR lpLibFileName", "HANDLE hFile", "DWORD dwFlags");
    "LoadLibraryExW" => "HMODULE"("LPCWSTR lpLibFileName", "HANDLE hFile", "DWORD dwFlags");
    "FreeLibrary" => "BOOL"("HMODULE hLibModule");
    "GetModuleHandleA" => "HMODULE"("LPCSTR lpModuleName");
    "GetModuleHandleW" => "HMODULE"("LPCWSTR lpModuleName");
    "GetModuleHandleExW" => "BOOL"("DWORD dwFlags", "LPCWSTR lpModuleName", "HMODULE *phModule");
    "GetModuleFileNameA" => "DWORD"("HMODULE hModule", "LPSTR lpFilename", "DWORD nSize");
    "GetModuleFileNameW" => "DWORD"("HMODULE hModule", "LPWSTR lpFilename", "DWORD nSize");
    "CreateProcessA" => "BOOL"("LPCSTR lpApplicationName", "LPSTR lpCommandLine", "LPSECURITY_ATTRIBUTES lpProcessAttributes", "LPSECURITY_ATTRIBUTES lpThreadAttributes", "BOOL bInheritHandles", "DWORD dwCreationFlags", "LPVOID lpEnvironment", "LPCSTR lpCurrentDirectory", "LPSTARTUPINFOA lpStartupInfo", "LPPROCESS_INFORMATION lpProcessInformation");
    "CreateProcessW" => "BOOL"("LPCWSTR lpApplicationName", "LPWSTR lpCommandLine", "LPSECURITY_ATTRIBUTES lpProcessAttributes", "LPSECURITY_ATTRIBUTES lpThreadAttributes", "BOOL bInheritHandles", "DWORD dwCreationFlags", "LPVOID lpEnvironment", "LPCWSTR lpCurrentDirectory", "LPSTARTUPINFOW lpStartupInfo", "LPPROCESS_INFORMATION lpProcessInformation");
    "OpenProcess" => "HANDLE"("DWORD dwDesiredAccess", "BOOL bInheritHandle", "DWORD dwProcessId");
    "TerminateProcess" => "BOOL"("HANDLE hProcess", "UINT uExitCode");
    "ExitProcess" => "void"("UINT uExitCode");
    "GetCurrentProcess" => "HANDLE"();
    "GetCurrentProcessId" => "DWORD"();
    "GetCurrentThreadId" => "DWORD"();
    "CreateThread" => "HANDLE"("LPSECURITY_ATTRIBUTES lpThreadAttributes", "SIZE_T dwStackSize", "LPTHREAD_START_ROUTINE lpStartAddress", "LPVOID lpParameter", "DWORD dwCreationFlags", "LPDWORD lpThreadId");
    "CreateRemoteThread" => "HANDLE"("HANDLE hProcess", "LPSECURITY_ATTRIBUTES lpThreadAttributes", "SIZE_T dwStackSize", "LPTHREAD_START_ROUTINE lpStartAddress", "LPVOID lpParameter", "DWORD dwCreationFlags", "LPDWORD lpThreadId");
    "ResumeThread" => "DWORD"("HANDLE hThread");
    "SuspendThread" => "DWORD"("HANDLE hThread");
    "WriteProcessMemory" => "BOOL"("HANDLE hProcess", "LPVOID lpBaseAddress", "LPCVOID lpBuffer", "SIZE_T nSize", "SIZE_T *lpNumberOfBytesWritten");
    "ReadProcessMemory" => "BOOL"("HANDLE hProcess", "LPCVOID lpBaseAddress", "LPVOID lpBuffer", "SIZE_T nSize", "SIZE_T *lpNumberOfBytesRead");
    "WaitForSingleObject" => "DWORD"("HANDLE hHandle", "DWORD dwMilliseconds");
    "WaitForMultipleObjects" => "DWORD"("DWORD nCount", "const HANDLE *lpHandles", "BOOL bWaitAll", "DWORD dwMilliseconds");
    "Sleep" => "void"("DWORD dwMilliseconds");
    "CreateMutexW" => "HANDLE"("LPSECURITY_ATTRIBUTES lpMutexAttributes", "BOOL bInitialOwner", "LPCWSTR lpName");
    "CreateMutexA" => "HANDLE"("LPSECURITY_ATTRIBUTES lpMutexAttributes", "BOOL bInitialOwner", "LPCSTR lpName");
    "OpenMutexW" => "HANDLE"("DWORD dwDesiredAccess", "BOOL bInheritHandle", "LPCWSTR lpName");
    "CreateEventW" => "HANDLE"("LPSECURITY_ATTRIBUTES lpEventAttributes", "BOOL bManualReset", "BOOL bInitialState", "LPCWSTR lpName");
    "SetEvent" => "BOOL"("HANDLE hEvent");
    "GetLastError" => "DWORD"();
    "SetLastError" => "void"("DWORD dwErrCode");
    "GetCommandLineW" => "LPWSTR"();
    "GetCommandLineA" => "LPSTR"();
    "GetEnvironmentVariableW" => "DWORD"("LPCWSTR lpName", "LPWSTR lpBuffer", "DWORD nSize");
    "ExpandEnvironmentStringsW" => "DWORD"("LPCWSTR lpSrc", "LPWSTR lpDst", "DWORD nSize");
    "OutputDebugStringA" => "void"("LPCSTR lpOutputString");
    "OutputDebugStringW" => "void"("LPCWSTR lpOutputString");
    "IsDebuggerPresent" => "BOOL"();
    "CheckRemoteDebuggerPresent" => "BOOL"("HANDLE hProcess", "PBOOL pbDebuggerPresent");
    "GetTickCount" => "DWORD"();
    "GetTickCount64" => "ULONGLONG"();
    "QueryPerformanceCounter" => "BOOL"("LARGE_INTEGER *lpPerformanceCount");
    "GetSystemTimeAsFileTime" => "void"("LPFILETIME lpSystemTimeAsFileTime");
    "MultiByteToWideChar" => "int"("UINT CodePage", "DWORD dwFlags", "LPCCH lpMultiByteStr", "int cbMultiByte", "LPWSTR lpWideCharStr", "int cchWideChar");
    "WideCharToMultiByte" => "int"("UINT CodePage", "DWORD dwFlags", "LPCWCH lpWideCharStr", "int cchWideChar", "LPSTR lpMultiByteStr", "int cbMultiByte", "LPCCH lpDefaultChar", "LPBOOL lpUsedDefaultChar");
    "lstrlenW" => "int"("LPCWSTR lpString");
    "lstrcpyW" => "LPWSTR"("LPWSTR lpString1", "LPCWSTR lpString2");
    "EnterCriticalSection" => "void"("LPCRITICAL_SECTION lpCriticalSection");
    "LeaveCriticalSection" => "void"("LPCRITICAL_SECTION lpCriticalSection");
    "InitializeCriticalSection" => "void"("LPCRITICAL_SECTION lpCriticalSection");
    "TlsAlloc" => "DWORD"();
    "TlsGetValue" => "LPVOID"("DWORD dwTlsIndex");
    "TlsSetValue" => "BOOL"("DWORD dwTlsIndex", "LPVOID lpTlsValue");
    // advapi32
    "RegOpenKeyExW" => "LSTATUS"("HKEY hKey", "LPCWSTR lpSubKey", "DWORD ulOptions", "REGSAM samDesired", "PHKEY phkResult");
    "RegOpenKeyExA" => "LSTATUS"("HKEY hKey", "LPCSTR lpSubKey", "DWORD ulOptions", "REGSAM samDesired", "PHKEY phkResult");
    "RegCreateKeyExW" => "LSTATUS"("HKEY hKey", "LPCWSTR lpSubKey", "DWORD Reserved", "LPWSTR lpClass", "DWORD dwOptions", "REGSAM samDesired", "LPSECURITY_ATTRIBUTES lpSecurityAttributes", "PHKEY phkResult", "LPDWORD lpdwDisposition");
    "RegQueryValueExW" => "LSTATUS"("HKEY hKey", "LPCWSTR lpValueName", "LPDWORD lpReserved", "LPDWORD lpType", "LPBYTE lpData", "LPDWORD lpcbData");
    "RegSetValueExW" => "LSTATUS"("HKEY hKey", "LPCWSTR lpValueName", "DWORD Reserved", "DWORD dwType", "const BYTE *lpData", "DWORD cbData");
    "RegDeleteValueW" => "LSTATUS"("HKEY hKey", "LPCWSTR lpValueName");
    "RegCloseKey" => "LSTATUS"("HKEY hKey");
    "OpenProcessToken" => "BOOL"("HANDLE ProcessHandle", "DWORD DesiredAccess", "PHANDLE TokenHandle");
    "AdjustTokenPrivileges" => "BOOL"("HANDLE TokenHandle", "BOOL DisableAllPrivileges", "PTOKEN_PRIVILEGES NewState", "DWORD BufferLength", "PTOKEN_PRIVILEGES PreviousState", "PDWORD ReturnLength");
    "LookupPrivilegeValueW" => "BOOL"("LPCWSTR lpSystemName", "LPCWSTR lpName", "PLUID lpLuid");
    "CryptAcquireContextW" => "BOOL"("HCRYPTPROV *phProv", "LPCWSTR szContainer", "LPCWSTR szProvider", "DWORD dwProvType", "DWORD dwFlags");
    "CryptGenRandom" => "BOOL"("HCRYPTPROV hProv", "DWORD dwLen", "BYTE *pbBuffer");
    "OpenSCManagerW" => "SC_HANDLE"("LPCWSTR lpMachineName", "LPCWSTR lpDatabaseName", "DWORD dwDesiredAccess");
    "CreateServiceW" => "SC_HANDLE"("SC_HANDLE hSCManager", "LPCWSTR lpServiceName", "LPCWSTR lpDisplayName", "DWORD dwDesiredAccess", "DWORD dwServiceType", "DWORD dwStartType", "DWORD dwErrorControl", "LPCWSTR lpBinaryPathName", "LPCWSTR lpLoadOrderGroup", "LPDWORD lpdwTagId", "LPCWSTR lpDependencies", "LPCWSTR lpServiceStartName", "LPCWSTR lpPassword");
    // user32 / shell32
    "MessageBoxA" => "int"("HWND hWnd", "LPCSTR lpText", "LPCSTR lpCaption", "UINT uType");
    "MessageBoxW" => "int"("HWND hWnd", "LPCWSTR lpText", "LPCWSTR lpCaption", "UINT uType");
    "CreateWindowExW" => "HWND"("DWORD dwExStyle", "LPCWSTR lpClassName", "LPCWSTR lpWindowName", "DWORD dwStyle", "int X", "int Y", "int nWidth", "int nHeight", "HWND hWndParent", "HMENU hMenu", "HINSTANCE hInstance", "LPVOID lpParam");
    "ShowWindow" => "BOOL"("HWND hWnd", "int nCmdShow");
    "GetMessageW" => "BOOL"("LPMSG lpMsg", "HWND hWnd", "UINT wMsgFilterMin", "UINT wMsgFilterMax");
    "DispatchMessageW" => "LRESULT"("const MSG *lpMsg");
    "TranslateMessage" => "BOOL"("const MSG *lpMsg");
    "SendMessageW" => "LRESULT"("HWND hWnd", "UINT Msg", "WPARAM wParam", "LPARAM lParam");
    "PostMessageW" => "BOOL"("HWND hWnd", "UINT Msg", "WPARAM wParam", "LPARAM lParam");
    "FindWindowW" => "HWND"("LPCWSTR lpClassName", "LPCWSTR lpWindowName");
    "SetWindowsHookExW" => "HHOOK"("int idHook", "HOOKPROC lpfn", "HINSTANCE hmod", "DWORD dwThreadId");
    "GetAsyncKeyState" => "SHORT"("int vKey");
    "ShellExecuteW" => "HINSTANCE"("HWND hwnd", "LPCWSTR lpOperation", "LPCWSTR lpFile", "LPCWSTR lpParameters", "LPCWSTR lpDirectory", "INT nShowCmd");
    "ShellExecuteExW" => "BOOL"("SHELLEXECUTEINFOW *pExecInfo");
    "SHGetFolderPathW" => "HRESULT"("HWND hwnd", "int csidl", "HANDLE hToken", "DWORD dwFlags", "LPWSTR pszPath");
    // networking
    "WSAStartup" => "int"("WORD wVersionRequested", "LPWSADATA lpWSAData");
    "socket" => "SOCKET"("int af", "int type", "int protocol");
    "connect" => "int"("SOCKET s", "const sockaddr *name", "int namelen");
    "bind" => "int"("SOCKET s", "const sockaddr *addr", "int namelen");
    "listen" => "int"("SOCKET s", "int backlog");
    "accept" => "SOCKET"("SOCKET s", "sockaddr *addr", "int *addrlen");
    "send" => "int"("SOCKET s", "const char *buf", "int len", "int flags");
    "recv" => "int"("SOCKET s", "char *buf", "int len", "int flags");
    "closesocket" => "int"("SOCKET s");
    "getaddrinfo" => "int"("PCSTR pNodeName", "PCSTR pServiceName", "const ADDRINFOA *pHints", "PADDRINFOA *ppResult");
    "gethostbyname" => "hostent *"("const char *name");
    "inet_addr" => "unsigned long"("const char *cp");
    "htons" => "u_short"("u_short hostshort");
    "InternetOpenW" => "HINTERNET"("LPCWSTR lpszAgent", "DWORD dwAccessType", "LPCWSTR lpszProxy", "LPCWSTR lpszProxyBypass", "DWORD dwFlags");
    "InternetOpenUrlW" => "HINTERNET"("HINTERNET hInternet", "LPCWSTR lpszUrl", "LPCWSTR lpszHeaders", "DWORD dwHeadersLength", "DWORD dwFlags", "DWORD_PTR dwContext");
    "InternetConnectW" => "HINTERNET"("HINTERNET hInternet", "LPCWSTR lpszServerName", "INTERNET_PORT nServerPort", "LPCWSTR lpszUserName", "LPCWSTR lpszPassword", "DWORD dwService", "DWORD dwFlags", "DWORD_PTR dwContext");
    "InternetReadFile" => "BOOL"("HINTERNET hFile", "LPVOID lpBuffer", "DWORD dwNumberOfBytesToRead", "LPDWORD lpdwNumberOfBytesRead");
    "HttpOpenRequestW" => "HINTERNET"("HINTERNET hConnect", "LPCWSTR lpszVerb", "LPCWSTR lpszObjectName", "LPCWSTR lpszVersion", "LPCWSTR lpszReferrer", "LPCWSTR *lplpszAcceptTypes", "DWORD dwFlags", "DWORD_PTR dwContext");
    "HttpSendRequestW" => "BOOL"("HINTERNET hRequest", "LPCWSTR lpszHeaders", "DWORD dwHeadersLength", "LPVOID lpOptional", "DWORD dwOptionalLength");
    "URLDownloadToFileW" => "HRESULT"("LPUNKNOWN pCaller", "LPCWSTR szURL", "LPCWSTR szFileName", "DWORD dwReserved", "LPBINDSTATUSCALLBACK lpfnCB");
    // ntdll
    "NtQueryInformationProcess" => "NTSTATUS"("HANDLE ProcessHandle", "PROCESSINFOCLASS ProcessInformationClass", "PVOID ProcessInformation", "ULONG ProcessInformationLength", "PULONG ReturnLength");
    "NtAllocateVirtualMemory" => "NTSTATUS"("HANDLE ProcessHandle", "PVOID *BaseAddress", "ULONG_PTR ZeroBits", "PSIZE_T RegionSize", "ULONG AllocationType", "ULONG Protect");
    "RtlCopyMemory" => "void"("void *Destination", "const void *Source", "SIZE_T Length");
    // C runtime
    "malloc" => "void *"("size_t size");
    "calloc" => "void *"("size_t count", "size_t size");
    "realloc" => "void *"("void *ptr", "size_t size");
    "free" => "void"("void *ptr");
    "memcpy" => "void *"("void *dest", "const void *src", "size_t n");
    "memmove" => "void *"("void *dest", "const void *src", "size_t n");
    "memset" => "void *"("void *s", "int c", "size_t n");
    "memcmp" => "int"("const void *s1", "const void *s2", "size_t n");
    "memchr" => "void *"("const void *s", "int c", "size_t n");
    "strlen" => "size_t"("const char *s");
    "wcslen" => "size_t"("const wchar_t *s");
    "strcpy" => "char *"("char *dest", "const char *src");
    "strncpy" => "char *"("char *dest", "const char *src", "size_t n");
    "strcat" => "char *"("char *dest", "const char *src");
    "strcmp" => "int"("const char *s1", "const char *s2");
    "strncmp" => "int"("const char *s1", "const char *s2", "size_t n");
    "strchr" => "char *"("const char *s", "int c");
    "strrchr" => "char *"("const char *s", "int c");
    "strstr" => "char *"("const char *haystack", "const char *needle");
    "strdup" => "char *"("const char *s");
    "strtol" => "long"("const char *nptr", "char **endptr", "int base");
    "strtoul" => "unsigned long"("const char *nptr", "char **endptr", "int base");
    "atoi" => "int"("const char *nptr");
    "printf" => "int"("const char *format", "...");
    "fprintf" => "int"("FILE *stream", "const char *format", "...");
    "sprintf" => "int"("char *str", "const char *format", "...");
    "snprintf" => "int"("char *str", "size_t size", "const char *format", "...");
    "__fprintf_chk" => "int"("FILE *stream", "int flag", "const char *format", "...");
    "__printf_chk" => "int"("int flag", "const char *format", "...");
    "__sprintf_chk" => "int"("char *str", "int flag", "size_t slen", "const char *format", "...");
    "puts" => "int"("const char *s");
    "fputs" => "int"("const char *s", "FILE *stream");
    "fopen" => "FILE *"("const char *pathname", "const char *mode");
    "fclose" => "int"("FILE *stream");
    "fread" => "size_t"("void *ptr", "size_t size", "size_t nmemb", "FILE *stream");
    "fwrite" => "size_t"("const void *ptr", "size_t size", "size_t nmemb", "FILE *stream");
    "fgets" => "char *"("char *s", "int size", "FILE *stream");
    "fseek" => "int"("FILE *stream", "long offset", "int whence");
    "ftell" => "long"("FILE *stream");
    "open" => "int"("const char *pathname", "int flags", "...");
    "close" => "int"("int fd");
    "read" => "ssize_t"("int fd", "void *buf", "size_t count");
    "write" => "ssize_t"("int fd", "const void *buf", "size_t count");
    "lseek" => "off_t"("int fd", "off_t offset", "int whence");
    "stat" => "int"("const char *pathname", "struct stat *statbuf");
    "unlink" => "int"("const char *pathname");
    "getenv" => "char *"("const char *name");
    "system" => "int"("const char *command");
    "exit" => "void"("int status");
    "abort" => "void"();
    "fork" => "pid_t"();
    "execve" => "int"("const char *pathname", "char *const argv[]", "char *const envp[]");
    "execvp" => "int"("const char *file", "char *const argv[]");
    "waitpid" => "pid_t"("pid_t pid", "int *wstatus", "int options");
    "kill" => "int"("pid_t pid", "int sig");
    "signal" => "sighandler_t"("int signum", "sighandler_t handler");
    "mmap" => "void *"("void *addr", "size_t length", "int prot", "int flags", "int fd", "off_t offset");
    "munmap" => "int"("void *addr", "size_t length");
    "mprotect" => "int"("void *addr", "size_t len", "int prot");
    "dlopen" => "void *"("const char *filename", "int flags");
    "dlsym" => "void *"("void *handle", "const char *symbol");
    "pthread_create" => "int"("pthread_t *thread", "const pthread_attr_t *attr", "void *(*start_routine)(void *)", "void *arg");
    "pthread_mutex_lock" => "int"("pthread_mutex_t *mutex");
    "pthread_mutex_unlock" => "int"("pthread_mutex_t *mutex");
    "time" => "time_t"("time_t *tloc");
    "srand" => "void"("unsigned int seed");
    "rand" => "int"();
    "qsort" => "void"("void *base", "size_t nmemb", "size_t size", "int (*compar)(const void *, const void *)");
    "setlocale" => "char *"("int category", "const char *locale");
    "bindtextdomain" => "char *"("const char *domainname", "const char *dirname");
    "textdomain" => "char *"("const char *domainname");
    "gettext" => "char *"("const char *msgid");
    "__libc_start_main" => "int"("int (*main)(int, char **, char **)", "int argc", "char **argv", "void (*init)(void)", "void (*fini)(void)", "void (*rtld_fini)(void)", "void *stack_end");
    // POSIX and bionic: processes, files, memory, time
    "execv" => "int"("const char *pathname", "char *const argv[]");
    "getpid" => "pid_t"();
    "getppid" => "pid_t"();
    "getuid" => "uid_t"();
    "geteuid" => "uid_t"();
    "setuid" => "int"("uid_t uid");
    "sigaction" => "int"("int signum", "const struct sigaction *act", "struct sigaction *oldact");
    "sigaltstack" => "int"("const stack_t *ss", "stack_t *old_ss");
    "ptrace" => "long"("int request", "pid_t pid", "void *addr", "void *data");
    "prctl" => "int"("int option", "unsigned long arg2", "unsigned long arg3", "unsigned long arg4", "unsigned long arg5");
    "syscall" => "long"("long number", "...");
    "getauxval" => "unsigned long"("unsigned long type");
    "fstat" => "int"("int fd", "struct stat *statbuf");
    "lstat" => "int"("const char *pathname", "struct stat *statbuf");
    "access" => "int"("const char *pathname", "int mode");
    "chmod" => "int"("const char *pathname", "mode_t mode");
    "chown" => "int"("const char *pathname", "uid_t owner", "gid_t group");
    "readlink" => "ssize_t"("const char *pathname", "char *buf", "size_t bufsiz");
    "symlink" => "int"("const char *target", "const char *linkpath");
    "rename" => "int"("const char *oldpath", "const char *newpath");
    "mkdir" => "int"("const char *pathname", "mode_t mode");
    "rmdir" => "int"("const char *pathname");
    "opendir" => "DIR *"("const char *name");
    "readdir" => "struct dirent *"("DIR *dirp");
    "closedir" => "int"("DIR *dirp");
    "getcwd" => "char *"("char *buf", "size_t size");
    "chdir" => "int"("const char *path");
    "dup" => "int"("int oldfd");
    "dup2" => "int"("int oldfd", "int newfd");
    "pipe" => "int"("int pipefd[2]");
    "fcntl" => "int"("int fd", "int cmd", "...");
    "ioctl" => "int"("int fd", "unsigned long request", "...");
    "poll" => "int"("struct pollfd *fds", "nfds_t nfds", "int timeout");
    "select" => "int"("int nfds", "fd_set *readfds", "fd_set *writefds", "fd_set *exceptfds", "struct timeval *timeout");
    "epoll_create1" => "int"("int flags");
    "epoll_ctl" => "int"("int epfd", "int op", "int fd", "struct epoll_event *event");
    "epoll_wait" => "int"("int epfd", "struct epoll_event *events", "int maxevents", "int timeout");
    "inotify_init1" => "int"("int flags");
    "memfd_create" => "int"("const char *name", "unsigned int flags");
    "madvise" => "int"("void *addr", "size_t length", "int advice");
    "mlock" => "int"("const void *addr", "size_t len");
    "uname" => "int"("struct utsname *buf");
    "gettimeofday" => "int"("struct timeval *tv", "struct timezone *tz");
    "clock_gettime" => "int"("clockid_t clockid", "struct timespec *tp");
    "nanosleep" => "int"("const struct timespec *req", "struct timespec *rem");
    "usleep" => "int"("useconds_t usec");
    "sleep" => "unsigned int"("unsigned int seconds");
    "setenv" => "int"("const char *name", "const char *value", "int overwrite");
    "atexit" => "int"("void (*function)(void)");
    "_exit" => "void"("int status");
    "dladdr" => "int"("const void *addr", "Dl_info *info");
    "dlclose" => "int"("void *handle");
    "__cxa_atexit" => "int"("void (*func)(void *)", "void *arg", "void *dso_handle");
    "__cxa_finalize" => "void"("void *dso_handle");
    "__stack_chk_fail" => "void"();
    // Apple: Objective-C runtime
    "objc_msgSend" => "id"("id self", "SEL op", "...");
    "objc_retain" => "id"("id obj");
    "objc_release" => "void"("id obj");
    "objc_autorelease" => "id"("id obj");
    "objc_retainAutoreleasedReturnValue" => "id"("id obj");
    "objc_autoreleasePoolPush" => "void *"();
    "objc_autoreleasePoolPop" => "void"("void *pool");
    "objc_alloc" => "id"("Class cls");
    "objc_alloc_init" => "id"("Class cls");
    "objc_getClass" => "Class"("const char *name");
    "objc_lookUpClass" => "Class"("const char *name");
    "objc_storeStrong" => "void"("id *location", "id obj");
    "sel_registerName" => "SEL"("const char *str");
    "sel_getName" => "const char *"("SEL sel");
    "class_getName" => "const char *"("Class cls");
    "class_getInstanceMethod" => "Method"("Class cls", "SEL name");
    "method_setImplementation" => "IMP"("Method m", "IMP imp");
    "method_exchangeImplementations" => "void"("Method m1", "Method m2");
    "object_getClass" => "Class"("id obj");
    "NSLog" => "void"("NSString *format", "...");
    // Apple: libdispatch, Core Foundation, Mach, Security, IOKit, dyld
    "dispatch_async" => "void"("dispatch_queue_t queue", "dispatch_block_t block");
    "dispatch_sync" => "void"("dispatch_queue_t queue", "dispatch_block_t block");
    "dispatch_after" => "void"("dispatch_time_t when", "dispatch_queue_t queue", "dispatch_block_t block");
    "dispatch_once" => "void"("dispatch_once_t *predicate", "dispatch_block_t block");
    "dispatch_get_global_queue" => "dispatch_queue_t"("long identifier", "unsigned long flags");
    "dispatch_queue_create" => "dispatch_queue_t"("const char *label", "dispatch_queue_attr_t attr");
    "dispatch_semaphore_create" => "dispatch_semaphore_t"("long value");
    "dispatch_semaphore_wait" => "long"("dispatch_semaphore_t dsema", "dispatch_time_t timeout");
    "dispatch_semaphore_signal" => "long"("dispatch_semaphore_t dsema");
    "dispatch_time" => "dispatch_time_t"("dispatch_time_t when", "int64_t delta");
    "CFRetain" => "CFTypeRef"("CFTypeRef cf");
    "CFRelease" => "void"("CFTypeRef cf");
    "CFStringCreateWithCString" => "CFStringRef"("CFAllocatorRef alloc", "const char *cStr", "CFStringEncoding encoding");
    "CFStringGetCString" => "Boolean"("CFStringRef theString", "char *buffer", "CFIndex bufferSize", "CFStringEncoding encoding");
    "CFStringGetLength" => "CFIndex"("CFStringRef theString");
    "CFDictionaryGetValue" => "const void *"("CFDictionaryRef theDict", "const void *key");
    "CFDictionaryCreateMutable" => "CFMutableDictionaryRef"("CFAllocatorRef allocator", "CFIndex capacity", "const CFDictionaryKeyCallBacks *keyCallBacks", "const CFDictionaryValueCallBacks *valueCallBacks");
    "CFDictionarySetValue" => "void"("CFMutableDictionaryRef theDict", "const void *key", "const void *value");
    "CFArrayGetCount" => "CFIndex"("CFArrayRef theArray");
    "CFArrayGetValueAtIndex" => "const void *"("CFArrayRef theArray", "CFIndex idx");
    "CFDataCreate" => "CFDataRef"("CFAllocatorRef allocator", "const UInt8 *bytes", "CFIndex length");
    "CFBundleGetMainBundle" => "CFBundleRef"();
    "CFBundleGetValueForInfoDictionaryKey" => "CFTypeRef"("CFBundleRef bundle", "CFStringRef key");
    "mach_task_self" => "mach_port_t"();
    "mach_absolute_time" => "uint64_t"();
    "mach_vm_allocate" => "kern_return_t"("vm_map_t target", "mach_vm_address_t *address", "mach_vm_size_t size", "int flags");
    "mach_vm_protect" => "kern_return_t"("vm_map_t target_task", "mach_vm_address_t address", "mach_vm_size_t size", "boolean_t set_maximum", "vm_prot_t new_protection");
    "mach_vm_write" => "kern_return_t"("vm_map_t target_task", "mach_vm_address_t address", "vm_offset_t data", "mach_msg_type_number_t dataCnt");
    "mach_vm_read_overwrite" => "kern_return_t"("vm_map_t target_task", "mach_vm_address_t address", "mach_vm_size_t size", "mach_vm_address_t data", "mach_vm_size_t *outsize");
    "task_for_pid" => "kern_return_t"("mach_port_t target_tport", "int pid", "mach_port_t *t");
    "task_info" => "kern_return_t"("task_name_t target_task", "task_flavor_t flavor", "task_info_t task_info_out", "mach_msg_type_number_t *task_info_outCnt");
    "proc_pidinfo" => "int"("int pid", "int flavor", "uint64_t arg", "void *buffer", "int buffersize");
    "sysctl" => "int"("int *name", "u_int namelen", "void *oldp", "size_t *oldlenp", "void *newp", "size_t newlen");
    "sysctlbyname" => "int"("const char *name", "void *oldp", "size_t *oldlenp", "void *newp", "size_t newlen");
    "SecItemCopyMatching" => "OSStatus"("CFDictionaryRef query", "CFTypeRef *result");
    "SecItemAdd" => "OSStatus"("CFDictionaryRef attributes", "CFTypeRef *result");
    "SecItemDelete" => "OSStatus"("CFDictionaryRef query");
    "SecRandomCopyBytes" => "int"("SecRandomRef rnd", "size_t count", "void *bytes");
    "CC_SHA256" => "unsigned char *"("const void *data", "CC_LONG len", "unsigned char *md");
    "CC_MD5" => "unsigned char *"("const void *data", "CC_LONG len", "unsigned char *md");
    "CCCrypt" => "CCCryptorStatus"("CCOperation op", "CCAlgorithm alg", "CCOptions options", "const void *key", "size_t keyLength", "const void *iv", "const void *dataIn", "size_t dataInLength", "void *dataOut", "size_t dataOutAvailable", "size_t *dataOutMoved");
    "IOServiceMatching" => "CFMutableDictionaryRef"("const char *name");
    "IOServiceGetMatchingService" => "io_service_t"("mach_port_t mainPort", "CFDictionaryRef matching");
    "IORegistryEntryCreateCFProperty" => "CFTypeRef"("io_registry_entry_t entry", "CFStringRef key", "CFAllocatorRef allocator", "IOOptionBits options");
    "_dyld_image_count" => "uint32_t"();
    "_dyld_get_image_name" => "const char *"("uint32_t image_index");
    "_dyld_get_image_header" => "const struct mach_header *"("uint32_t image_index");
    "_dyld_register_func_for_add_image" => "void"("void (*func)(const struct mach_header *, intptr_t)");
    // Android: log, properties, assets, native window, JNI entry points
    "__android_log_print" => "int"("int prio", "const char *tag", "const char *fmt", "...");
    "__android_log_write" => "int"("int prio", "const char *tag", "const char *text");
    "__android_log_vprint" => "int"("int prio", "const char *tag", "const char *fmt", "va_list ap");
    "__android_log_assert" => "void"("const char *cond", "const char *tag", "const char *fmt", "...");
    "__system_property_get" => "int"("const char *name", "char *value");
    "__system_property_find" => "const prop_info *"("const char *name");
    "__system_property_read" => "int"("const prop_info *pi", "char *name", "char *value");
    "android_dlopen_ext" => "void *"("const char *filename", "int flags", "const android_dlextinfo *extinfo");
    "android_set_abort_message" => "void"("const char *msg");
    "AAssetManager_fromJava" => "AAssetManager *"("JNIEnv *env", "jobject assetManager");
    "AAssetManager_open" => "AAsset *"("AAssetManager *mgr", "const char *filename", "int mode");
    "AAsset_read" => "int"("AAsset *asset", "void *buf", "size_t count");
    "AAsset_getLength" => "off_t"("AAsset *asset");
    "AAsset_close" => "void"("AAsset *asset");
    "ANativeWindow_fromSurface" => "ANativeWindow *"("JNIEnv *env", "jobject surface");
    "ANativeWindow_lock" => "int32_t"("ANativeWindow *window", "ANativeWindow_Buffer *outBuffer", "ARect *inOutDirtyBounds");
    "ANativeWindow_unlockAndPost" => "int32_t"("ANativeWindow *window");
    "ALooper_forThread" => "ALooper *"();
    "ALooper_pollOnce" => "int"("int timeoutMillis", "int *outFd", "int *outEvents", "void **outData");
    "JNI_OnLoad" => "jint"("JavaVM *vm", "void *reserved");
    "JNI_OnUnload" => "void"("JavaVM *vm", "void *reserved");
    "AndroidBitmap_getInfo" => "int"("JNIEnv *env", "jobject jbitmap", "AndroidBitmapInfo *info");
    "AndroidBitmap_lockPixels" => "int"("JNIEnv *env", "jobject jbitmap", "void **addrPtr");
};

/// Looks up a prototype by (possibly decorated) name: `__imp_`, a leading `_`
/// (Mach-O / cdecl), `@N` stdcall suffixes and ELF symbol versions are ignored.
pub fn lookup(name: &str) -> Option<&'static Proto> {
    let n = name.strip_prefix("__imp_").unwrap_or(name);
    let n = n.strip_prefix("j_").unwrap_or(n);
    let n = n.split("@@").next().unwrap_or(n);
    let n = n.split('@').next().unwrap_or(n);
    let find = |n: &str| PROTOS.iter().find(|(k, _)| *k == n).map(|(_, p)| p);
    find(n).or_else(|| n.strip_prefix('_').and_then(find))
}

/// The parameter's name: `LPCWSTR lpFileName` → `lpFileName`.
pub fn param_name(p: &str) -> &str {
    p.rsplit([' ', '*']).next().unwrap_or(p).trim_end_matches("[]")
}

/// `HANDLE CreateFileW(LPCWSTR lpFileName, …)`
pub fn signature(name: &str, p: &Proto) -> String {
    format!("{} {}({})", p.ret, name, p.params.join(", "))
}

// ------------------------------------------------------------------------------------------------
// Call-site annotation

/// Which argument a register or stack store carries, per calling convention.
fn arg_index(arch: Arch, format: Format, dst: &str) -> Option<usize> {
    // `qword ptr [rsp+0x20]` → `[rsp+0x20]`
    let d = dst.rsplit("ptr ").next().unwrap_or(dst).trim();
    match arch {
        Arch::X86_64 if format == Format::Pe => match d {
            "rcx" | "ecx" | "cx" | "cl" => Some(0),
            "rdx" | "edx" | "dx" | "dl" => Some(1),
            "r8" | "r8d" | "r8w" | "r8b" => Some(2),
            "r9" | "r9d" | "r9w" | "r9b" => Some(3),
            _ => {
                // [rsp+0x20] is the fifth argument, then +8 per argument.
                let off = d.strip_prefix("[rsp+0x")?.strip_suffix(']')?;
                let off = u64::from_str_radix(off, 16).ok()?;
                (off >= 0x20 && off % 8 == 0).then(|| 4 + ((off - 0x20) / 8) as usize)
            }
        },
        Arch::X86_64 => match d {
            "rdi" | "edi" | "di" | "dil" => Some(0),
            "rsi" | "esi" | "si" | "sil" => Some(1),
            "rdx" | "edx" | "dx" | "dl" => Some(2),
            "rcx" | "ecx" | "cx" | "cl" => Some(3),
            "r8" | "r8d" | "r8w" | "r8b" => Some(4),
            "r9" | "r9d" | "r9w" | "r9b" => Some(5),
            _ => None,
        },
        _ => None,
    }
}

fn callee_name(bin: &Binary, ins: &Instruction) -> Option<String> {
    let t = ins.target?;
    if let Some(&i) = bin.import_slots.get(&t) {
        return Some(bin.info.imports[i].name.clone());
    }
    let a = bin.analysis.as_ref()?;
    if let Some(&fi) = a.by_start.get(&t) {
        if let Some(&ii) = a.functions[fi].thunk_slot.and_then(|s| bin.import_slots.get(&s)) {
            return Some(bin.info.imports[ii].name.clone());
        }
    }
    bin.name_at(t)
}

impl Binary {
    /// Labels argument set-up with parameter names and calls with prototypes.
    pub(crate) fn annotate_calls(&self, insns: &mut [Instruction]) {
        if matches!(self.info.arch, Arch::X86 | Arch::X86_64) {
            self.annotate_calls_x86(insns);
        }
        if matches!(self.info.arch, Arch::Arm | Arch::Thumb) && !self.svd_ranges.is_empty() {
            self.annotate_mmio_arm(insns);
        }
        self.apply_operand_formats(insns);
    }

    /// Names memory-mapped registers in ARM / Thumb listings, from a loaded SVD file: a literal-pool load of a
    /// peripheral address (`ldr r0, [pc, #4]` where the pool holds 0x40020000) is annotated, and so is every
    /// `ldr` / `str` through a register that holds one (`ldr r1, [r0, #0x14]` → `GPIOA_ODR`). The register
    /// values are tracked within the listing and forgotten at labels, branches and when overwritten.
    fn annotate_mmio_arm(&self, insns: &mut [Instruction]) {
        let mut known: HashMap<String, u64> = HashMap::new();
        let is_reg = |s: &str| {
            let s = s.trim();
            s.len() >= 2
                && s.len() <= 3
                && (s.starts_with('r') && s[1..].bytes().all(|b| b.is_ascii_digit()) || matches!(s, "sp" | "lr" | "ip" | "fp" | "sl"))
        };
        let imm = |s: &str| -> Option<i64> {
            let t = s.trim().trim_start_matches('#');
            let (neg, t) = t.strip_prefix('-').map_or((false, t), |r| (true, r));
            let v = if let Some(h) = t.strip_prefix("0x") { i64::from_str_radix(h, 16).ok()? } else { t.parse().ok()? };
            Some(if neg { -v } else { v })
        };
        for ins in insns.iter_mut() {
            if ins.label.is_some() {
                known.clear();
            }
            let text: String = ins.operands.iter().map(|t| t.t.as_str()).collect();
            let m = ins.mnemonic.as_str();
            let load = m.starts_with("ldr");
            let store = m.starts_with("str");
            let (dest, rest) = match text.split_once(',') {
                Some((d, r)) => (d.trim().to_string(), r.trim().to_string()),
                None => (text.trim().to_string(), String::new()),
            };
            let mut note: Option<String> = None;
            if (load || store) && rest.starts_with('[') {
                let inner = rest.trim_start_matches('[').split(']').next().unwrap_or("");
                let mut parts = inner.split(',').map(str::trim);
                let (b, off) = (parts.next().unwrap_or(""), parts.next());
                if b == "pc" {
                    // A literal-pool load: the pool word is the constant.
                    if load {
                        if let Some(v) = ins.target.and_then(|t| self.bytes_at(t)).and_then(|d| d.get(..4)).map(|d| {
                            let w = [d[0], d[1], d[2], d[3]];
                            if self.info.endian == crate::model::Endian::Big {
                                u32::from_be_bytes(w)
                            } else {
                                u32::from_le_bytes(w)
                            }
                        }) {
                            known.insert(dest.clone(), v as u64);
                            // A pointer to a peripheral's start names the peripheral, not its first register.
                            note =
                                self.svd_ranges.iter().find(|r| r.0 == v as u64).map(|r| r.2.clone()).or_else(|| self.mmio_name(v as u64));
                        } else {
                            known.remove(&dest);
                        }
                    }
                } else if let Some(&c) = known.get(b) {
                    let delta = match off {
                        None => Some(0),
                        Some(o) if !is_reg(o) => imm(o),
                        _ => None,
                    };
                    if let Some(d) = delta {
                        note = self.mmio_name(c.wrapping_add(d as u64));
                    }
                    if load {
                        known.remove(&dest);
                    }
                } else if load {
                    known.remove(&dest);
                }
            } else if matches!(m, "adds" | "add" | "subs" | "sub") && is_reg(&dest) {
                // rD = rS ± imm keeps a known constant (`adds r0, r1, #4`, `adds r0, #4`).
                let ops: Vec<&str> = rest.split(',').map(str::trim).collect();
                let (src, k) = match ops.as_slice() {
                    [k] => (dest.as_str(), imm(k)),
                    [s, k] if is_reg(s) => (*s, imm(k)),
                    _ => ("", None),
                };
                match (known.get(src).copied(), k) {
                    (Some(c), Some(k)) => {
                        let v = if m.starts_with("sub") { c.wrapping_sub(k as u64) } else { c.wrapping_add(k as u64) };
                        known.insert(dest.clone(), v);
                    }
                    _ => {
                        known.remove(&dest);
                    }
                }
            } else if matches!(m, "mov" | "movs") && is_reg(&dest) {
                match known.get(rest.as_str()).copied() {
                    Some(c) => {
                        known.insert(dest.clone(), c);
                    }
                    None => {
                        known.remove(&dest);
                    }
                }
            } else if !(store || m.starts_with("cmp") || m.starts_with("tst") || m.starts_with('b') && !m.starts_with("bic"))
                && is_reg(&dest)
            {
                known.remove(&dest);
            }
            if matches!(ins.flow, Flow::Call | Flow::Jump | Flow::CondJump | Flow::Ret) {
                // A call clobbers the caller-saved registers; a branch ends the straight-line stretch.
                known.clear();
            }
            if let Some(n) = note {
                ins.comment = Some(match ins.comment.take() {
                    Some(c) => format!("{c} · {n}"),
                    None => n,
                });
            }
        }
    }

    fn annotate_calls_x86(&self, insns: &mut [Instruction]) {
        for i in 0..insns.len() {
            if insns[i].mnemonic != "call" {
                continue;
            }
            let Some(name) = callee_name(self, &insns[i]) else { continue };
            let Some(proto) = lookup(&name) else { continue };
            let pretty = crate::demangle(&name).unwrap_or(name.clone());
            let sig = signature(&pretty, proto);
            insns[i].comment = Some(match insns[i].comment.take() {
                Some(c) if !c.contains('!') => format!("{c} · {sig}"),
                _ => sig,
            });
            // Walk back through the same basic block.
            let mut pushes = 0usize;
            let mut done = vec![false; proto.params.len()];
            for j in (0..i).rev().take(24) {
                let prev = &insns[j];
                if prev.mnemonic == "call" || prev.flow != crate::model::Flow::None {
                    break;
                }
                // A labelled instruction starts the block: handle it, then stop.
                let block_start = prev.label.is_some();
                let idx = if self.info.arch == Arch::X86 {
                    (prev.mnemonic == "push").then(|| {
                        pushes += 1;
                        pushes - 1
                    })
                } else {
                    let writes = matches!(
                        prev.mnemonic.as_str(),
                        "mov" | "lea" | "xor" | "movzx" | "movsx" | "movsxd" | "or" | "and" | "add" | "sub" | "movaps" | "movups"
                    );
                    if !writes {
                        None
                    } else {
                        // Punctuation tokens are merged (`], `), so split the text, not the tokens.
                        let text: String = prev.operands.iter().map(|t| t.t.as_str()).collect();
                        let dst = text.split(',').next().unwrap_or("");
                        arg_index(self.info.arch, self.info.format, dst)
                    }
                };
                if let Some(idx) = idx.filter(|&k| k < proto.params.len() && !done[k]) {
                    done[idx] = true;
                    let pname = param_name(proto.params[idx]).to_string();
                    crate::operands::symbolize_argument(self, &mut insns[j], &name, &pname);
                    let c = &mut insns[j].comment;
                    *c = Some(match c.take() {
                        Some(old) => format!("{pname} = {old}"),
                        None => pname,
                    });
                }
                if block_start {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        assert_eq!(lookup("CreateFileW").unwrap().params.len(), 7);
        assert!(lookup("__imp_CreateFileW").is_some());
        assert!(lookup("_malloc").is_some());
        assert!(lookup("memcpy@@GLIBC_2.14").is_some());
        assert!(lookup("j_strlen").is_some());
        assert_eq!(param_name("LPCWSTR lpFileName"), "lpFileName");
        assert_eq!(param_name("char *const argv[]"), "argv");
        assert!(lookup("NotAnApi").is_none());
    }

    #[test]
    fn apple_and_android_apis_are_known() {
        // Mach-O symbols carry a leading underscore; bionic and Apple names resolve like the rest.
        assert_eq!(lookup("_objc_msgSend").unwrap().params, &["id self", "SEL op", "..."]);
        assert_eq!(lookup("_dispatch_async").unwrap().params.len(), 2);
        assert_eq!(lookup("_CFStringCreateWithCString").unwrap().ret, "CFStringRef");
        assert_eq!(lookup("__android_log_print").unwrap().params.len(), 4);
        assert_eq!(lookup("AAssetManager_open").unwrap().params.len(), 3);
        assert_eq!(lookup("_sysctlbyname").unwrap().params.len(), 5);
        assert!(lookup("ptrace").is_some() && lookup("JNI_OnLoad").is_some());
    }

    #[test]
    fn every_prototype_is_well_formed_and_named_once() {
        let mut seen = std::collections::HashSet::new();
        for (name, p) in PROTOS {
            assert!(seen.insert(*name), "{name} is listed twice");
            assert!(!p.ret.is_empty(), "{name}: no return type");
            for (i, param) in p.params.iter().enumerate() {
                assert!(!param.trim().is_empty(), "{name}: empty parameter");
                // `...` only as the last parameter.
                assert!(*param != "..." || i + 1 == p.params.len(), "{name}: `...` is not last");
                assert!(!param.contains(';') && !param.contains('{'), "{name}: {param}");
            }
        }
    }
}
