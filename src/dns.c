// DNS packet parsing (hardened: no unaligned access, bounded compression)
#include "dns.h"
#include "stats.h"
#include "logger.h"
#include "security.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

// DNS name compression pointer flag
#define DNS_COMPRESSION_MASK 0xC0
#define DNS_MAX_JUMPS 64

// Forward declaration
static int parse_dns_name(const u_char *data, int data_len, int *offset, char *name, int name_size);

static u_short read_u16(const u_char *data, int data_len, int *offset, int *ok) {
    if (*offset + 2 > data_len) { *ok = 0; return 0; }
    u_short v;
    memcpy(&v, data + *offset, 2);
    *offset += 2;
    return ntohs(v);
}

static u_int read_u32(const u_char *data, int data_len, int *offset, int *ok) {
    if (*offset + 4 > data_len) { *ok = 0; return 0; }
    u_int v;
    memcpy(&v, data + *offset, 4);
    *offset += 4;
    return ntohl(v);
}

// Parse DNS record
static int parse_dns_rr(const u_char *data, int data_len, int *offset, int is_question) {
    char name[256] = {0};
    int name_len = parse_dns_name(data, data_len, offset, name, sizeof(name));

    if (name_len < 0 || *offset + (is_question ? 4 : 10) > data_len) {
        return -1;
    }

    int ok = 1;
    u_short type = read_u16(data, data_len, offset, &ok);
    u_short class = read_u16(data, data_len, offset, &ok);
    if (!ok) return -1;

    if (is_question) {
        sanitize_printable(name, sizeof(name));
        printf("     Question: %s (Type=%u, Class=%u)\n", name, type, class);
        security_dns_name(security_peer_src(), name, type, 1, 0);
        return 0;
    }

    // Answer records
    u_int ttl = read_u32(data, data_len, offset, &ok);
    u_short rdlength = read_u16(data, data_len, offset, &ok);
    if (!ok) return -1;

    if (*offset + rdlength > data_len) {
        return -1;
    }

    sanitize_printable(name, sizeof(name));
    printf("     Answer: %s (Type=%u, Class=%u, TTL=%u)\n", name, type, class, ttl);

    switch (type) {
        case DNS_TYPE_A: {
            if (rdlength == 4) {
                struct in_addr addr;
                memcpy(&addr, data + *offset, 4);
                char ip_str[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)))
                    printf("         A: %s\n", ip_str);
            }
            break;
        }
        case DNS_TYPE_AAAA: {
            if (rdlength == 16) {
                struct in6_addr addr;
                memcpy(&addr, data + *offset, 16);
                char ip_str[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str)))
                    printf("         AAAA: %s\n", ip_str);
            }
            break;
        }
        case DNS_TYPE_CNAME: {
            char cname[256] = {0};
            int temp_offset = *offset;
            if (parse_dns_name(data, data_len, &temp_offset, cname, sizeof(cname)) >= 0) {
                sanitize_printable(cname, sizeof(cname));
                printf("         CNAME: %s\n", cname);
            }
            break;
        }
        case DNS_TYPE_MX: {
            if (rdlength >= 2) {
                int tmp = *offset;
                int ok2 = 1;
                u_short preference = read_u16(data, data_len, &tmp, &ok2);
                char mx_name[256] = {0};
                if (ok2 && parse_dns_name(data, data_len, &tmp, mx_name, sizeof(mx_name)) >= 0) {
                    sanitize_printable(mx_name, sizeof(mx_name));
                    printf("         MX: %s (preference %u)\n", mx_name, preference);
                }
            }
            break;
        }
        case DNS_TYPE_NS: {
            char ns_name[256] = {0};
            int temp_offset = *offset;
            if (parse_dns_name(data, data_len, &temp_offset, ns_name, sizeof(ns_name)) >= 0) {
                sanitize_printable(ns_name, sizeof(ns_name));
                printf("         NS: %s\n", ns_name);
            }
            break;
        }
        case DNS_TYPE_PTR: {
            char ptr_name[256] = {0};
            int temp_offset = *offset;
            if (parse_dns_name(data, data_len, &temp_offset, ptr_name, sizeof(ptr_name)) >= 0) {
                sanitize_printable(ptr_name, sizeof(ptr_name));
                printf("         PTR: %s\n", ptr_name);
            }
            break;
        }
        case DNS_TYPE_TXT: {
            printf("         TXT: ");
            const u_char *txt_data = data + *offset;
            int txt_len = rdlength;
            while (txt_len > 0) {
                int str_len = *txt_data++;
                txt_len--;
                if (str_len <= 0 || str_len > txt_len) break;
                char chunk[256];
                int cp = str_len < (int)sizeof(chunk) - 1 ? str_len : (int)sizeof(chunk) - 1;
                memcpy(chunk, txt_data, cp);
                chunk[cp] = '\0';
                sanitize_printable(chunk, sizeof(chunk));
                printf("\"%s\" ", chunk);
                txt_data += str_len;
                txt_len -= str_len;
            }
            printf("\n");
            break;
        }
        default: {
            printf("         Type %u: %u bytes of data\n", type, rdlength);
            break;
        }
    }

    *offset += rdlength;
    return 0;
}

// Parse DNS name (bounds-checked, jump-limited, name-size-checked)
static int parse_dns_name(const u_char *data, int data_len, int *offset, char *name, int name_size) {
    int name_pos = 0;
    int jumped = 0;
    int jump_offset = 0;
    int jumps = 0;
    if (name_size > 0) name[0] = '\0';

    while (*offset < data_len && name_pos < name_size - 1) {
        u_char len = data[*offset];

        if (len == 0) {
            (*offset)++;
            break;
        }

        if ((len & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK) {  // Compression pointer
            if (*offset + 1 >= data_len) return -1;
            if (++jumps > DNS_MAX_JUMPS) return -1;

            if (!jumped) {
                jump_offset = *offset + 2;
                jumped = 1;
            }

            u_short raw;
            memcpy(&raw, data + *offset, 2);
            u_short pointer = ntohs(raw) & 0x3FFF;
            if (pointer >= data_len) return -1;

            // Validate pointer target is a valid label start (not a compression pointer)
            u_char target_len = data[pointer];
            if ((target_len & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK) return -1;
            if (target_len > 63) return -1;
            if (pointer + 1 + target_len > data_len) return -1;

            *offset = pointer;
            continue;
        }

        // Plain label: top bits must be 00
        if (len & DNS_COMPRESSION_MASK) return -1;
        if (len > 63) return -1;
        if (*offset + 1 + len > data_len) return -1;
        // name buffer: need len + (1 dot?) + 1 NUL
        if (name_pos + (name_pos > 0 ? 1 : 0) + len >= name_size) return -1;

        (*offset)++;

        if (name_pos > 0) {
            name[name_pos++] = '.';
        }

        memcpy(name + name_pos, data + *offset, len);
        name_pos += len;
        name[name_pos] = '\0';

        *offset += len;
    }

    if (jumped) {
        *offset = jump_offset;
    }

    return name_pos;
}

void parse_dns(const u_char *data, int size) {
    if (size < (int)sizeof(dns_header_t)) {
        printf("DNS: Truncated header\n");
        return;
    }

    stats_increment("DNS", (uint32_t)size);

    dns_header_t dns;
    memcpy(&dns, data, sizeof(dns));
    int offset = sizeof(dns_header_t);

    u_short flags = ntohs(dns.flags);
    int is_response = (flags & DNS_FLAG_QR) != 0;

    printf("DNS: %s (ID=0x%04X)\n",
           is_response ? "Response" : "Query",
           ntohs(dns.transaction_id));

    printf("     Flags: ");
    if (flags & DNS_FLAG_AA) printf("AA ");
    if (flags & DNS_FLAG_TC) printf("TC ");
    if (flags & DNS_FLAG_RD) printf("RD ");
    if (flags & DNS_FLAG_RA) printf("RA ");
    if (flags & DNS_FLAG_AD) printf("AD ");
    if (flags & DNS_FLAG_CD) printf("CD ");
    printf("(rcode=%u)\n", flags & 0xF);

    u_short questions = ntohs(dns.questions);
    u_short answers = ntohs(dns.answer_rrs);
    u_short authorities = ntohs(dns.authority_rrs);
    u_short additionals = ntohs(dns.additional_rrs);
    if (questions > 64) questions = 64;
    if (answers > 128) answers = 128;

    printf("     Questions: %u, Answers: %u, Authorities: %u, Additional: %u\n",
           ntohs(dns.questions), ntohs(dns.answer_rrs),
           authorities, additionals);

    for (int i = 0; i < questions && offset < size; i++) {
        if (parse_dns_rr(data, size, &offset, 1) != 0) {
            printf("     Error parsing question %d\n", i + 1);
            break;
        }
    }

    for (int i = 0; i < answers && offset < size; i++) {
        if (parse_dns_rr(data, size, &offset, 0) != 0) {
            printf("     Error parsing answer %d\n", i + 1);
            break;
        }
    }
    // Authorities/additionals skipped (offsets validated); counted above.
}
