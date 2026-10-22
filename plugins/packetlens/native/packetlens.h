#ifndef SENTINEL_PACKETLENS_H
#define SENTINEL_PACKETLENS_H
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#define PL_EXPORT __declspec(dllexport)
#else
#define PL_EXPORT __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define PL_TOP 6
#define PL_MAX_PCAP (8u * 1024u * 1024u)
typedef struct {
    char address[48];
    uint64_t packets;
    uint64_t bytes;
} PLSource;
typedef struct {
    uint16_t port;
    uint16_t protocol; /* 6 TCP, 17 UDP */
    uint64_t packets;
} PLPort;
typedef struct {
    uint64_t frames, wire_bytes, captured_bytes;
    uint64_t ipv4, ipv6, arp, tcp, udp, icmp, other;
    uint64_t malformed, tcp_syn, tcp_rst, dns, http, tls;
    uint64_t untracked_source_packets, untracked_port_packets;
    uint32_t source_count, port_count;
    PLSource sources[PL_TOP];
    PLPort ports[PL_TOP];
} PLReport;
/* Returns 0 on success, -1 bad arguments, -2 malformed PCAP, -3 unsupported link type. */
PL_EXPORT uint32_t packetlens_abi_version(void);
PL_EXPORT int packetlens_analyze(const uint8_t *pcap, size_t length, PLReport *out);
#ifdef __cplusplus
}
#endif
#endif
