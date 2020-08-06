#ifndef _HOSTSHIJACKING_DNS_H_
#define _HOSTSHIJACKING_DNS_H_

#include <stdbool.h>
#include <stdlib.h>

// Ref:
//  - https://www.ietf.org/rfc/rfc1035.txt

enum {
    _HOSTSHIJACKING_DNS_QR_QUERY = false,
    _HOSTSHIJACKING_DNS_QR_REPLY = true,
};
enum {
    _HOSTSHIJACKING_DNS_TC_QUERY = 0,
    _HOSTSHIJACKING_DNS_TC_REPLY = 1,
};

enum {
    _HOSTSHIJACKING_DNS_RCODE_OK = 0,
};
enum {
    _HOSTSHIJACKING_DNS_TYPE_A = 1,
    _HOSTSHIJACKING_DNS_TYPE_CNAME = 5,
    _HOSTSHIJACKING_DNS_TYPE_AAAA = 28,
};

struct _hostshijacking_dns_hdr {
    unsigned short id;  // A 16 bit identifier assigned by the program that
                        // generates any kind of query.
    unsigned char qr;  // A one bit field that specifies whether this message is
                       // a query (0), or a response(1).
    unsigned char opcode;  // 4 bits field that specifies kind of query.
    bool aa;  // Authoritative Answer - this bit is valid in responses.
    bool tc;  // 1 bit. TrunCation - specifies that this message was truncated
              // due to length..
    bool rd;  // 1 bit. Recursion Desired.
    bool ra;  // 1 bit. Recursion Available.
    unsigned char z;      // 3 bits, reserved.
    unsigned char rcode;  // 4 bits response code.

    // An unsigned 16 bit integer specifying the number of entries in the
    // question section.
    unsigned short qdcount;
    // An unsigned 16 bit integer specifying the number of resource records in
    // the answer section.
    unsigned short ancount;
    // An unsigned 16 bit integer specifying the number of name server resource
    // records in the authority records section.
    unsigned short nscount;
    // An unsigned 16 bit integer specifying the number of resource records in
    // the additional records section.
    unsigned short arcount;
};

struct _hostshijacking_dns_question {
    char *name;
    unsigned short type;
    unsigned short _class;
};

struct _hostshijacking_dns_resource_record {
    char *name;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short rdlength;
    union {
        unsigned int ipv4;
        unsigned char ipv6[16];
        char *other;  // not null terminated.
    } data;
};

struct _hostshijacking_dns_reply {
    struct _hostshijacking_dns_hdr hdr;
    struct _hostshijacking_dns_question **qds;
    struct _hostshijacking_dns_resource_record **ans;
    struct _hostshijacking_dns_resource_record **nss;
    struct _hostshijacking_dns_resource_record **ars;
};

struct _hostshijacking_dns_reply *_hostshijacking_decode_dns_reply(
    const char *buf, unsigned int bufsz, unsigned int *pos);
void _hostshijacking_free_dns_reply(struct _hostshijacking_dns_reply *reply);
size_t _hostshijacking_encode_dns_reply(
    const struct _hostshijacking_dns_reply *reply, char *buf, unsigned int cap);

#endif
