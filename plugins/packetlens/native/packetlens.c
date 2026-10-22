/* Offline PCAP Ethernet/IPv4/IPv6 statistics. No network sockets or capture API. */
#include "packetlens.h"
#include <stdio.h>
#include <string.h>
#define MAX_TRACKED 256
#define MAX_FRAME 262144u
typedef struct {
    PLSource sources[MAX_TRACKED];
    PLPort ports[MAX_TRACKED];
    size_t source_count, port_count;
} PLTrack;

static uint16_t be16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static uint32_t read32(const uint8_t *p, int little) {
    if (little) return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static void source_add(PLTrack *t, PLReport *r, const char *ip, size_t bytes) {
    size_t i;
    for (i = 0; i < t->source_count; ++i) {
        if (strcmp(t->sources[i].address, ip) == 0) break;
    }
    if (i == t->source_count) {
        if (t->source_count == MAX_TRACKED) { r->untracked_source_packets++; return; }
        ++t->source_count;
        memcpy(t->sources[i].address, ip, strlen(ip) + 1);
    }
    t->sources[i].packets++;
    t->sources[i].bytes += bytes;
}
static void port_add(PLTrack *t, PLReport *r, uint16_t proto, uint16_t port) {
    size_t i;
    for (i = 0; i < t->port_count; ++i) {
        if (t->ports[i].port == port && t->ports[i].protocol == proto) break;
    }
    if (i == t->port_count) {
        if (t->port_count == MAX_TRACKED) { r->untracked_port_packets++; return; }
        ++t->port_count;
        t->ports[i].port = port;
        t->ports[i].protocol = proto;
    }
    t->ports[i].packets++;
}
static void handle_transport(const uint8_t *p, size_t n, uint8_t proto,
                             PLTrack *t, PLReport *r) {
    if (proto == 6) {
        r->tcp++;
        if (n < 20) { r->malformed++; return; }
        uint16_t port = be16(p + 2);
        if ((p[12] >> 4) < 5 || ((size_t)(p[12] >> 4) * 4) > n) {
            r->malformed++; return;
        }
        port_add(t, r, proto, port);
        if ((p[13] & 0x02) && !(p[13] & 0x10)) r->tcp_syn++;
        if (p[13] & 0x04) r->tcp_rst++;
        if (port == 80) r->http++;
        if (port == 443) r->tls++;
        if (port == 53) r->dns++;
    } else if (proto == 17) {
        r->udp++;
        if (n < 8) { r->malformed++; return; }
        uint16_t port = be16(p + 2);
        port_add(t, r, proto, port);
        if (port == 53) r->dns++;
        if (port == 443) r->tls++;
    } else if (proto == 1 || proto == 58) {
        r->icmp++;
    } else {
        r->other++;
    }
}
static void ipv4(const uint8_t *p, size_t n, size_t bytes, PLTrack *t, PLReport *r) {
    char ip[48];
    size_t header_len;
    uint16_t total;
    r->ipv4++;
    if (n < 20 || (p[0] >> 4) != 4) { r->malformed++; return; }
    header_len = (size_t)(p[0] & 0x0f) * 4;
    total = be16(p + 2);
    if (header_len < 20 || header_len > n || total < header_len) { r->malformed++; return; }
    (void)snprintf(ip, sizeof ip, "%u.%u.%u.%u", p[12], p[13], p[14], p[15]);
    source_add(t, r, ip, bytes);
    if (total > n) { r->malformed++; return; }
    /* Non-initial IPv4 fragments do not contain an L4 header. */
    if ((be16(p + 6) & 0x1fff) != 0) { r->other++; return; }
    handle_transport(p + header_len, total - header_len, p[9], t, r);
}
static void ipv6(const uint8_t *p, size_t n, size_t bytes, PLTrack *t, PLReport *r) {
    char ip[48];
    uint16_t payload_len;
    r->ipv6++;
    if (n < 40 || (p[0] >> 4) != 6) { r->malformed++; return; }
    payload_len = be16(p + 4);
    (void)snprintf(ip, sizeof ip, "%x:%x:%x:%x:%x:%x:%x:%x",
        be16(p + 8), be16(p + 10), be16(p + 12), be16(p + 14),
        be16(p + 16), be16(p + 18), be16(p + 20), be16(p + 22));
    source_add(t, r, ip, bytes);
    if ((size_t)payload_len > n - 40) { r->malformed++; return; }
    /* IPv6 extension headers and jumbograms are not decoded in v1. */
    if (p[6] == 0 || p[6] == 43 || p[6] == 44 || p[6] == 60 || p[6] == 51) {
        r->other++; return;
    }
    handle_transport(p + 40, payload_len, p[6], t, r);
}
static void frame(const uint8_t *p, size_t n, size_t wire_len, PLTrack *t, PLReport *r) {
    size_t off = 14;
    uint16_t ethertype;
    int tags = 0;
    r->frames++;
    r->wire_bytes += wire_len;
    r->captured_bytes += n;
    if (n < off) { r->malformed++; return; }
    ethertype = be16(p + 12);
    while ((ethertype == 0x8100 || ethertype == 0x88a8) && tags < 2) {
        if (n - off < 4) { r->malformed++; return; }
        ethertype = be16(p + off + 2);
        off += 4;
        ++tags;
    }
    if (ethertype == 0x0800) ipv4(p + off, n - off, wire_len, t, r);
    else if (ethertype == 0x86dd) ipv6(p + off, n - off, wire_len, t, r);
    else if (ethertype == 0x0806) r->arp++;
    else r->other++;
}
static void summarize(const PLTrack *t, PLReport *r) {
    size_t i, j, count;
    count = t->source_count < PL_TOP ? t->source_count : PL_TOP;
    for (i = 0; i < count; ++i) {
        size_t best = MAX_TRACKED;
        for (j = 0; j < t->source_count; ++j) {
            size_t k;
            int selected = 0;
            for (k = 0; k < i; ++k)
                if (strcmp(r->sources[k].address, t->sources[j].address) == 0) selected = 1;
            if (selected) continue;
            if (best == MAX_TRACKED || t->sources[j].packets > t->sources[best].packets ||
                (t->sources[j].packets == t->sources[best].packets &&
                 strcmp(t->sources[j].address, t->sources[best].address) < 0)) best = j;
        }
        if (best == MAX_TRACKED) break;
        r->sources[i] = t->sources[best];
        r->source_count++;
    }
    count = t->port_count < PL_TOP ? t->port_count : PL_TOP;
    for (i = 0; i < count; ++i) {
        size_t best = MAX_TRACKED;
        for (j = 0; j < t->port_count; ++j) {
            size_t k;
            int selected = 0;
            for (k = 0; k < i; ++k)
                if (r->ports[k].port == t->ports[j].port &&
                    r->ports[k].protocol == t->ports[j].protocol) selected = 1;
            if (selected) continue;
            if (best == MAX_TRACKED || t->ports[j].packets > t->ports[best].packets ||
                (t->ports[j].packets == t->ports[best].packets &&
                 (t->ports[j].protocol < t->ports[best].protocol ||
                  (t->ports[j].protocol == t->ports[best].protocol &&
                   t->ports[j].port < t->ports[best].port)))) best = j;
        }
        if (best == MAX_TRACKED) break;
        r->ports[i] = t->ports[best];
        r->port_count++;
    }
}
PL_EXPORT uint32_t packetlens_abi_version(void) { return 1u; }
PL_EXPORT int packetlens_analyze(const uint8_t *pcap, size_t length, PLReport *out) {
    int little;
    uint32_t snaplen;
    size_t off = 24;
    PLTrack tracker;
    if (!pcap || !out) return -1;
    memset(out, 0, sizeof *out);
    if (length < 24 || length > PL_MAX_PCAP) return -2;
    if (pcap[0] == 0xd4 && pcap[1] == 0xc3 && pcap[2] == 0xb2 && pcap[3] == 0xa1) little = 1;
    else if (pcap[0] == 0xa1 && pcap[1] == 0xb2 && pcap[2] == 0xc3 && pcap[3] == 0xd4) little = 0;
    else if (pcap[0] == 0x4d && pcap[1] == 0x3c && pcap[2] == 0xb2 && pcap[3] == 0xa1) little = 1;
    else if (pcap[0] == 0xa1 && pcap[1] == 0xb2 && pcap[2] == 0x3c && pcap[3] == 0x4d) little = 0;
    else return -2;
    if ((little && (pcap[4] != 2 || pcap[5] != 0 || pcap[6] != 4 || pcap[7] != 0)) ||
        (!little && (pcap[4] != 0 || pcap[5] != 2 || pcap[6] != 0 || pcap[7] != 4))) return -2;
    snaplen = read32(pcap + 16, little);
    if (snaplen == 0 || snaplen > MAX_FRAME) return -2;
    if (read32(pcap + 20, little) != 1) return -3; /* Ethernet only. */
    memset(&tracker, 0, sizeof tracker);
    while (off < length) {
        uint32_t incl, original;
        if (length - off < 16) return -2;
        incl = read32(pcap + off + 8, little);
        original = read32(pcap + off + 12, little);
        off += 16;
        if (incl > snaplen || incl > MAX_FRAME || incl > length - off ||
            original < incl || original > MAX_FRAME) return -2;
        frame(pcap + off, incl, original, &tracker, out);
        off += incl;
    }
    summarize(&tracker, out);
    return 0;
}
