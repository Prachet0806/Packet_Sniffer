// DNS packet parsing
#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// DNS name compression pointer flag
#define DNS_COMPRESSION_MASK 0xC0

// Forward declaration
static int parse_dns_name(const u_char *data, int data_len, int *offset, char *name, int name_size);

// Parse DNS record
static int parse_dns_rr(const u_char *data, int data_len, int *offset, int is_question) {
    char name[256] = {0};
    int name_len = parse_dns_name(data, data_len, offset, name, sizeof(name));

    if (name_len < 0 || *offset + (is_question ? 4 : 10) > data_len) {
        return -1;
    }

    // Read fields
    u_short type = ntohs(*(u_short*)(data + *offset)); *offset += 2;
    u_short class = ntohs(*(u_short*)(data + *offset)); *offset += 2;

    if (is_question) {
        printf("     Question: %s (Type=%u, Class=%u)\n", name, type, class);
        return 0;
    }

    // Answer records
    u_int ttl = ntohl(*(u_int*)(data + *offset)); *offset += 4;
    u_short rdlength = ntohs(*(u_short*)(data + *offset)); *offset += 2;

    if (*offset + rdlength > data_len) {
        return -1;
    }

    // Parse record data
    printf("     Answer: %s (Type=%u, Class=%u, TTL=%u)\n", name, type, class, ttl);

    switch (type) {
        case DNS_TYPE_A: {
            if (rdlength == 4) {
                struct in_addr addr;
                memcpy(&addr, data + *offset, 4);
                char ip_str[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)) != NULL) {
                    printf("         A: %s\n", ip_str);
                } else {
                    printf("         A: Invalid address\n");
                }
            }
            break;
        }
        case DNS_TYPE_AAAA: {
            if (rdlength == 16) {
                struct in6_addr addr;
                memcpy(&addr, data + *offset, 16);
                char ip_str[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str)) != NULL) {
                    printf("         AAAA: %s\n", ip_str);
                } else {
                    printf("         AAAA: Invalid address\n");
                }
            }
            break;
        }
        case DNS_TYPE_CNAME: {
            char cname[256] = {0};
            int temp_offset = *offset;
            parse_dns_name(data, data_len, &temp_offset, cname, sizeof(cname));
            printf("         CNAME: %s\n", cname);
            break;
        }
        case DNS_TYPE_MX: {
            if (rdlength >= 2) {
                u_short preference = ntohs(*(u_short*)(data + *offset));
                int temp_offset = *offset + 2;
                char mx_name[256] = {0};
                parse_dns_name(data, data_len, &temp_offset, mx_name, sizeof(mx_name));
                printf("         MX: %s (preference %u)\n", mx_name, preference);
            }
            break;
        }
        case DNS_TYPE_NS: {
            char ns_name[256] = {0};
            int temp_offset = *offset;
            parse_dns_name(data, data_len, &temp_offset, ns_name, sizeof(ns_name));
            printf("         NS: %s\n", ns_name);
            break;
        }
        case DNS_TYPE_PTR: {
            char ptr_name[256] = {0};
            int temp_offset = *offset;
            parse_dns_name(data, data_len, &temp_offset, ptr_name, sizeof(ptr_name));
            printf("         PTR: %s\n", ptr_name);
            break;
        }
        case DNS_TYPE_TXT: {
            printf("         TXT: ");
            const u_char *txt_data = data + *offset;
            int txt_len = rdlength;
            int original_txt_len = txt_len;
            while (txt_len > 0 && txt_len <= original_txt_len && txt_data < (data + data_len)) {
                if (txt_data >= (data + data_len)) break;
                int str_len = *txt_data++;
                txt_len--;
                if (str_len > 0 && str_len <= txt_len && txt_data + str_len <= (data + data_len)) {
                    printf("\"%.*s\" ", str_len, txt_data);
                    txt_data += str_len;
                    txt_len -= str_len;
                } else {
                    break;  // Invalid string length or out of bounds
                }
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

// Parse DNS name
static int parse_dns_name(const u_char *data, int data_len, int *offset, char *name, int name_size) {
    int name_pos = 0;
    int jumped = 0;
    int jump_offset = 0;
    int max_jumps = 16;  // Prevent infinite loops in compression pointers
    int jump_count = 0;

    while (*offset < data_len && name_pos < name_size - 1 && jump_count < max_jumps) {
        // Bounds check before accessing data
        if (*offset >= data_len) return -1;
        
        u_char len = data[*offset];

        if (len == 0) {
            (*offset)++;
            break;
        }

        if ((len & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK) {  // Compression pointer
            if (*offset + 1 >= data_len) return -1;

            if (!jumped) {
                jump_offset = *offset + 2;
                jumped = 1;
            }

            u_short pointer = ntohs(*(u_short*)(data + *offset)) & 0x3FFF;
            
            // Validate pointer: must be within packet bounds and not point backwards beyond original offset
            // Pointers can point to earlier in the packet (for compression), but not before the DNS header
            if (pointer >= data_len || pointer < 12) {  // 12 = DNS header size
                return -1;
            }
            
            // Prevent infinite loops: check if we've seen this pointer before (simple check)
            if (pointer == *offset) {
                return -1;  // Self-referencing pointer
            }

            jump_count++;
            *offset = pointer;
            continue;
        }

        // Validate label length (max 63 bytes per label)
        if (len > 63) {
            return -1;
        }

        if (*offset + len + 1 >= data_len) return -1;

        (*offset)++;

        if (name_pos > 0) {
            if (name_pos + 1 >= name_size) return -1;  // Check space for '.'
            name[name_pos++] = '.';
        }

        // Check if we have enough space for this label
        if (name_pos + len >= name_size - 1) {
            return -1;  // Name buffer would overflow
        }

        memcpy(name + name_pos, data + *offset, len);
        name_pos += len;
        name[name_pos] = '\0';

        *offset += len;
    }

    if (jump_count >= max_jumps) {
        return -1;  // Too many compression pointer jumps
    }

    if (jumped) {
        *offset = jump_offset;
    }

    // Ensure null termination
    if (name_pos < name_size) {
        name[name_pos] = '\0';
    }

    return name_pos;
}

void parse_dns(const u_char *data, int size) {
    if (size < (int)sizeof(dns_header_t)) {
        printf("DNS: Truncated header\n");
        return;
    }

    const dns_header_t *dns = (const dns_header_t *)data;
    int offset = sizeof(dns_header_t);

    // Parse flags
    u_short flags = ntohs(dns->flags);
    int is_response = (flags & DNS_FLAG_QR) != 0;
    int opcode = (flags >> 11) & 0xF;
    int rcode = flags & 0xF;

    printf("DNS: %s (ID=0x%04X)\n",
           is_response ? "Response" : "Query",
           ntohs(dns->transaction_id));

    // Flags
    printf("     Flags: ");
    if (flags & DNS_FLAG_AA) printf("AA ");
    if (flags & DNS_FLAG_TC) printf("TC ");
    if (flags & DNS_FLAG_RD) printf("RD ");
    if (flags & DNS_FLAG_RA) printf("RA ");
    if (flags & DNS_FLAG_AD) printf("AD ");
    if (flags & DNS_FLAG_CD) printf("CD ");
    printf("\n");

    // Record counts
    u_short questions = ntohs(dns->questions);
    u_short answers = ntohs(dns->answer_rrs);
    u_short authorities = ntohs(dns->authority_rrs);
    u_short additionals = ntohs(dns->additional_rrs);

    printf("     Questions: %u, Answers: %u, Authorities: %u, Additional: %u\n",
           questions, answers, authorities, additionals);

    // Parse questions
    for (int i = 0; i < questions && offset < size; i++) {
        if (parse_dns_rr(data, size, &offset, 1) != 0) {
            printf("     Error parsing question %d\n", i + 1);
            break;
        }
    }

    // Parse answers
    for (int i = 0; i < answers && offset < size; i++) {
        if (parse_dns_rr(data, size, &offset, 0) != 0) {
            printf("     Error parsing answer %d\n", i + 1);
            break;
        }
    }
}
