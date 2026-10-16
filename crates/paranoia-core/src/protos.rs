//! Built-in prototypes for common Windows and C library APIs. Used to label
//! argument set-up instructions (`; lpFileName`) and to give pseudocode calls
//! the right number of arguments — IDA does the same with its type libraries.

use crate::model::{Arch, Format, Instruction, TokenKind};
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
    // kernel32 — files
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
    // kernel32 — memory
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
    // kernel32 — processes, threads, modules
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
        if !matches!(self.info.arch, Arch::X86 | Arch::X86_64) {
            return;
        }
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
                        let dst: String = prev
                            .operands
                            .iter()
                            .take_while(|t| !(t.k == TokenKind::Punct && t.t.contains(',')))
                            .map(|t| t.t.as_str())
                            .collect();
                        arg_index(self.info.arch, self.info.format, &dst)
                    }
                };
                if let Some(idx) = idx.filter(|&k| k < proto.params.len() && !done[k]) {
                    done[idx] = true;
                    let pname = param_name(proto.params[idx]).to_string();
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
}
