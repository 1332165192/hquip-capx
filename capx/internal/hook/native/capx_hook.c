// capx_hook.dll — a pure-C TLS plaintext hook DLL injected into a target
// process. It inline-hooks OpenSSL/BoringSSL SSL_write / SSL_read (via MinHook)
// and streams the *plaintext* (before encrypt / after decrypt) back to capx over
// a local TCP channel (127.0.0.1:19092). No Go runtime, so it is safe to load
// into arbitrary processes via remote-thread injection. Frida/Python not needed.
//
// Wire frame to capx: [1 byte type][4 byte little-endian len][len bytes]
//   type 'H' hello   payload = "<pid>\t<exe name>"
//   type 'W' write   payload = plaintext sent by the app (request)
//   type 'R' read    payload = plaintext received by the app (response)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include "minhook/include/MinHook.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

#define CAPX_HOOK_PORT 19092

typedef int (*SSL_write_t)(void *ssl, const void *buf, int num);
typedef int (*SSL_read_t)(void *ssl, void *buf, int num);
static SSL_write_t real_SSL_write = NULL;
static SSL_read_t real_SSL_read = NULL;

static SOCKET g_sock = INVALID_SOCKET;
static CRITICAL_SECTION g_cs;
static int g_wsa = 0;

static SOCKET capx_connect(void) {
    if (!g_wsa) {
        WSADATA w;
        if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return INVALID_SOCKET;
        g_wsa = 1;
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(CAPX_HOOK_PORT);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static int send_all(SOCKET s, const char *p, int n) {
    int off = 0;
    while (off < n) {
        int k = send(s, p + off, n - off, 0);
        if (k <= 0) return 0;
        off += k;
    }
    return 1;
}

static void send_frame(char type, const unsigned char *data, int len) {
    EnterCriticalSection(&g_cs);
    if (g_sock == INVALID_SOCKET) g_sock = capx_connect();
    if (g_sock != INVALID_SOCKET) {
        unsigned char hdr[5];
        unsigned int n = (unsigned int)(len < 0 ? 0 : len);
        hdr[0] = (unsigned char)type;
        hdr[1] = n & 0xff; hdr[2] = (n >> 8) & 0xff; hdr[3] = (n >> 16) & 0xff; hdr[4] = (n >> 24) & 0xff;
        if (!send_all(g_sock, (const char *)hdr, 5) || (n > 0 && !send_all(g_sock, (const char *)data, (int)n))) {
            closesocket(g_sock);
            g_sock = INVALID_SOCKET;
        }
    }
    LeaveCriticalSection(&g_cs);
}

static int my_SSL_write(void *ssl, const void *buf, int num) {
    int ret = real_SSL_write(ssl, buf, num);
    if (ret > 0) send_frame('W', (const unsigned char *)buf, ret);
    return ret;
}

static int my_SSL_read(void *ssl, void *buf, int num) {
    int ret = real_SSL_read(ssl, buf, num);
    if (ret > 0) send_frame('R', (const unsigned char *)buf, ret);
    return ret;
}

// install_one scans every loaded module for an exported `name` and hooks the
// first match. Returns 1 on success.
static int install_one(const char *name, void **real, void *detour) {
    HMODULE mods[1024];
    DWORD cb = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &cb)) return 0;
    int count = (int)(cb / sizeof(HMODULE));
    for (int i = 0; i < count; i++) {
        FARPROC fn = GetProcAddress(mods[i], name);
        if (fn) {
            if (MH_CreateHook((LPVOID)fn, detour, real) == MH_OK && MH_EnableHook((LPVOID)fn) == MH_OK) {
                return 1;
            }
        }
    }
    return 0;
}

static void send_hello(void) {
    DWORD pid = GetCurrentProcessId();
    char exe[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    char *base = exe;
    for (char *p = exe; *p; p++) if (*p == '\\' || *p == '/') base = p + 1;
    char msg[MAX_PATH + 32];
    int n = _snprintf(msg, sizeof(msg), "%lu\t%s", (unsigned long)pid, base);
    if (n > 0) send_frame('H', (const unsigned char *)msg, n);
}

static DWORD WINAPI worker(LPVOID p) {
    (void)p;
    send_hello();
    if (MH_Initialize() != MH_OK) return 0;
    // SSL libraries may load lazily; retry resolving + hooking for a while.
    for (int tries = 0; tries < 30; tries++) {
        if (!real_SSL_write) install_one("SSL_write", (void **)&real_SSL_write, (void *)my_SSL_write);
        if (!real_SSL_read) install_one("SSL_read", (void **)&real_SSL_read, (void *)my_SSL_read);
        if (real_SSL_write && real_SSL_read) break;
        Sleep(1000);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        InitializeCriticalSection(&g_cs);
        CreateThread(NULL, 0, worker, NULL, 0, NULL);
    }
    return TRUE;
}
