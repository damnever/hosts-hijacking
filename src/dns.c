#include "dns.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LABEL_LENGTH 63
#define MAX_DOMAIN_LENGTH 253
#define DNS_HEADER_SIZE 12

struct _hostshijacking_dns_reply *decode_dns_reply(const char *buf,
                                                   unsigned int bufsz,
                                                   unsigned int *pos);
void free_dns_reply(struct _hostshijacking_dns_reply *reply);
size_t encode_dns_reply(const struct _hostshijacking_dns_reply *reply,
                        char *buf, unsigned int cap);

struct _hostshijacking_dns_reply *_hostshijacking_decode_dns_reply(
    const char *buf, unsigned int bufsz, unsigned int *pos) {
    return decode_dns_reply(buf, bufsz, pos);
}

void _hostshijacking_free_dns_reply(struct _hostshijacking_dns_reply *reply) {
    free_dns_reply(reply);
}

size_t _hostshijacking_encode_dns_reply(
    const struct _hostshijacking_dns_reply *reply, char *buf,
    unsigned int cap) {
    return encode_dns_reply(reply, buf, cap);
}

struct rbuf {
    const char *data;
    int pos;
    int size;
};

static struct rbuf *rbuf_from(const char *data, int size);
static struct rbuf *rbuf_copy_at(struct rbuf *b, int index);
static void rbuf_free(struct rbuf *b);
static int rbuf_pos(struct rbuf *b);
static int rbuf_read_u8(struct rbuf *b, unsigned char *v);
static int rbuf_read_u16(struct rbuf *b, unsigned short *v);
static int rbuf_read_u32(struct rbuf *b, unsigned int *v);
static int rbuf_read_mem(struct rbuf *b, char *buf, unsigned int size);
static int rbuf_read_u8_at(struct rbuf *b, unsigned int index,
                           unsigned char *v);
static int rbuf_read_u16_at(struct rbuf *b, unsigned int index,
                            unsigned short *v);
static int rbuf_read_mem_at(struct rbuf *b, unsigned int index, char *buf,
                            unsigned int size);
static int rbuf_skip(struct rbuf *b, unsigned int size);

struct wbuf {
    char *data;
    int pos;
    int size;
};

static struct wbuf *wbuf_from(char *data, int size);
static void wbuf_free(struct wbuf *b);
static int wbuf_pos(struct wbuf *b);
static int wbuf_write_u8(struct wbuf *b, unsigned char v);
static int wbuf_write_u16(struct wbuf *b, unsigned short v);
static int wbuf_write_u32(struct wbuf *b, unsigned int v);
static int wbuf_write_mem(struct wbuf *b, const char *buf, unsigned int size);
static int wbuf_write_mem_at(struct wbuf *b, unsigned int index,
                             const char *buf, unsigned int size);

static int decode_dns_hdr(struct rbuf *b, struct _hostshijacking_dns_hdr *hdr);
static int encode_dns_hdr(struct wbuf *b, struct _hostshijacking_dns_hdr hdr);
static char *decode_dns_domain_name(struct rbuf *b);
static int encode_dns_domain_name(struct wbuf *b, const char *buf);
static struct _hostshijacking_dns_question *decode_dns_question(
    struct rbuf *rbuf);
static int encode_dns_question(struct wbuf *b,
                               const struct _hostshijacking_dns_question *rr);
static struct _hostshijacking_dns_resource_record *decode_dns_resource_record(
    struct rbuf *b);
static int encode_dns_resource_record(
    struct wbuf *b, const struct _hostshijacking_dns_resource_record *rr);

struct _hostshijacking_dns_reply *decode_dns_reply(const char *buf,
                                                   unsigned int bufsz,
                                                   unsigned int *pos) {
    struct rbuf *rbuf = rbuf_from(buf, bufsz);
    if (rbuf == NULL) return NULL;

    struct _hostshijacking_dns_hdr hdr;
    memset(&hdr, 0, sizeof(struct _hostshijacking_dns_hdr));
    if (0 != decode_dns_hdr(rbuf, &hdr)) {
        rbuf_free(rbuf);
        return NULL;
    }
    if (hdr.qr != _HOSTSHIJACKING_DNS_QR_REPLY ||
        hdr.rcode != _HOSTSHIJACKING_DNS_RCODE_OK || hdr.ancount == 0) {
        rbuf_free(rbuf);
        return NULL;
    }
    int qdcount = hdr.qdcount;
    int ancount = hdr.ancount;
    int nscount = hdr.nscount;
    int arcount = hdr.arcount;

    struct _hostshijacking_dns_reply *reply =
        (struct _hostshijacking_dns_reply *)malloc(
            sizeof(struct _hostshijacking_dns_reply));
    memset(reply, 0, sizeof(struct _hostshijacking_dns_reply));
    hdr.qdcount = 0;
    hdr.ancount = 0;
    hdr.nscount = 0;
    hdr.arcount = 0;
    memcpy(&reply->hdr, &hdr, sizeof(hdr));
    reply->qds = NULL;
    reply->ans = NULL;
    reply->nss = NULL;
    reply->ars = NULL;

    if (qdcount > 0) {
        int sz = sizeof(struct _hostshijacking_dns_question *) * qdcount;
        reply->qds = malloc(sz);
        if (NULL == reply->qds) {
            rbuf_free(rbuf);
            free_dns_reply(reply);
            return NULL;
        }
        memset(reply->qds, 0, sz);
        for (; reply->hdr.qdcount < qdcount;) {
            if (NULL ==
                (reply->qds[reply->hdr.qdcount] = decode_dns_question(rbuf))) {
                break;
            }
            reply->hdr.qdcount += 1;
        }
    }
    if (ancount > 0) {
        int sz = sizeof(struct _hostshijacking_dns_resource_record *) * ancount;
        reply->ans = malloc(sz);
        if (NULL == reply->ans) {
            rbuf_free(rbuf);
            free_dns_reply(reply);
            return NULL;
        }
        memset(reply->ans, 0, sz);
        for (; reply->hdr.ancount < ancount;) {
            if (NULL == (reply->ans[reply->hdr.ancount] =
                             decode_dns_resource_record(rbuf))) {
                break;
            }
            reply->hdr.ancount += 1;
        }
    }
    if (nscount > 0) {
        int sz = sizeof(struct _hostshijacking_dns_resource_record *) * nscount;
        reply->nss = malloc(sz);
        if (NULL == reply->nss) {
            rbuf_free(rbuf);
            free_dns_reply(reply);
            return NULL;
        }
        memset(reply->nss, 0, sz);
        for (; reply->hdr.nscount < nscount;) {
            if (NULL == (reply->nss[reply->hdr.nscount] =
                             decode_dns_resource_record(rbuf))) {
                break;
            }
            reply->hdr.nscount += 1;
        }
    }
    if (arcount > 0) {
        int sz = sizeof(struct _hostshijacking_dns_resource_record *) * arcount;
        reply->ars = malloc(sz);
        if (NULL == reply->ars) {
            rbuf_free(rbuf);
            free_dns_reply(reply);
            return NULL;
        }
        memset(reply->ars, 0, sz);
        for (; reply->hdr.arcount < arcount;) {
            if (NULL == (reply->ars[reply->hdr.arcount] =
                             decode_dns_resource_record(rbuf))) {
                break;
            }
            reply->hdr.arcount += 1;
        }
    }

    unsigned int bufpos = rbuf_pos(rbuf);
    rbuf_free(rbuf);
    if (reply->hdr.qdcount != qdcount || reply->hdr.ancount != ancount ||
        reply->hdr.nscount != nscount || reply->hdr.arcount != arcount) {
        free_dns_reply(reply);
        return NULL;
    }
    *pos = bufpos;
    return reply;
}

void _free_dns_resource_record(struct _hostshijacking_dns_resource_record *rr) {
    if (NULL == rr) return;
    free(rr->name);
    switch (rr->type) {
        case _HOSTSHIJACKING_DNS_TYPE_A:
        case _HOSTSHIJACKING_DNS_TYPE_AAAA:
            break;
        default:
            if (NULL != rr->data.other) {
                free(rr->data.other);
            }
            break;
    }
    free(rr);
}

void free_dns_reply(struct _hostshijacking_dns_reply *reply) {
    assert(NULL != reply);
    if (reply->hdr.qdcount > 0) {
        for (int i = 0; i < reply->hdr.qdcount; i++) {
            free(reply->qds[i]->name);
            free(reply->qds[i]);
        }
        free(reply->qds);
    }
    if (reply->hdr.ancount > 0) {
        for (int i = 0; i < reply->hdr.ancount; i++) {
            _free_dns_resource_record(reply->ans[i]);
        }
        free(reply->ans);
    }
    if (reply->hdr.nscount > 0) {
        for (int i = 0; i < reply->hdr.nscount; i++) {
            _free_dns_resource_record(reply->nss[i]);
        }
        free(reply->nss);
    }
    if (reply->hdr.arcount > 0) {
        for (int i = 0; i < reply->hdr.arcount; i++) {
            _free_dns_resource_record(reply->ars[i]);
        }
        free(reply->ars);
    }
    free(reply);
}

size_t encode_dns_reply(const struct _hostshijacking_dns_reply *reply,
                        char *buf, unsigned int cap) {
    struct wbuf *wbuf = wbuf_from(buf, cap);
    if (wbuf == NULL) return -1;
    if (0 != encode_dns_hdr(wbuf, reply->hdr)) return -1;
    for (int i = 0; i < reply->hdr.qdcount; i++) {
        if (0 != encode_dns_question(wbuf, reply->qds[i])) {
            wbuf_free(wbuf);
            return -1;
        }
    }
    for (int i = 0; i < reply->hdr.ancount; i++) {
        if (0 != encode_dns_resource_record(wbuf, reply->ans[i])) {
            wbuf_free(wbuf);
            return -1;
        }
    }
    for (int i = 0; i < reply->hdr.nscount; i++) {
        if (0 != encode_dns_resource_record(wbuf, reply->nss[i])) {
            wbuf_free(wbuf);
            return -1;
        }
    }
    for (int i = 0; i < reply->hdr.arcount; i++) {
        if (0 != encode_dns_resource_record(wbuf, reply->ars[i])) {
            wbuf_free(wbuf);
            return -1;
        }
    }
    size_t sz = wbuf_pos(wbuf);
    wbuf_free(wbuf);
    return sz;
}

static int decode_dns_hdr(struct rbuf *rbuf,
                          struct _hostshijacking_dns_hdr *hdr) {
    if (0 != rbuf_read_u16(rbuf, &hdr->id)) return -1;
    unsigned short flags;
    if (0 != rbuf_read_u16(rbuf, &flags)) return -1;
    hdr->qr = 0x1 & (flags >> 15);
    hdr->opcode = 0xf & (flags >> 11);
    hdr->aa = 0x1 & (flags >> 10);
    hdr->tc = 0x1 & (flags >> 9);
    hdr->rd = 0x1 & (flags >> 8);
    hdr->ra = 0x1 & (flags >> 7);
    hdr->z = 0x7 & (flags >> 4);
    hdr->rcode = 0xf & (flags >> 0);
    if (0 != rbuf_read_u16(rbuf, &hdr->qdcount)) return -1;
    if (0 != rbuf_read_u16(rbuf, &hdr->ancount)) return -1;
    if (0 != rbuf_read_u16(rbuf, &hdr->nscount)) return -1;
    if (0 != rbuf_read_u16(rbuf, &hdr->arcount)) return -1;
    return 0;
}

static int encode_dns_hdr(struct wbuf *wbuf,
                          struct _hostshijacking_dns_hdr hdr) {
    if (0 != wbuf_write_u16(wbuf, hdr.id)) return -1;
    unsigned short flags = 0;
    flags |= ((0x1 & (unsigned short)hdr.qr) << 15);
    flags |= ((0xf & (unsigned short)hdr.opcode) << 11);
    flags |= ((0x1 & (unsigned short)hdr.aa) << 10);
    flags |= ((0x1 & (unsigned short)hdr.tc) << 9);
    flags |= ((0x1 & (unsigned short)hdr.rd) << 8);
    flags |= ((0x1 & (unsigned short)hdr.ra) << 7);
    flags |= ((0x7 & (unsigned short)hdr.z) << 4);
    flags |= 0xf & (unsigned short)hdr.rcode;
    if (0 != wbuf_write_u16(wbuf, flags)) return -1;
    if (0 != wbuf_write_u16(wbuf, hdr.qdcount)) return -1;
    if (0 != wbuf_write_u16(wbuf, hdr.ancount)) return -1;
    if (0 != wbuf_write_u16(wbuf, hdr.nscount)) return -1;
    if (0 != wbuf_write_u16(wbuf, hdr.arcount)) return -1;
    return 0;
}

static char *decode_dns_domain_name(struct rbuf *rbuf) {
    char namebuf[MAX_DOMAIN_LENGTH];
    int pos = 0;
    unsigned char labelsz;
    char label[MAX_LABEL_LENGTH];
    bool adddot = false;
    struct rbuf *newbbuf = rbuf;

    for (; true;) {
        if (0 != rbuf_read_u8(newbbuf, &labelsz)) return NULL;
        if (labelsz == 0) break;
        // TODO(damnever): check if label greater than 63.
        if ((0x3 & (labelsz >> 6)) > 0) {  // Compression pointer.
            unsigned short pointer;
            if (0 != rbuf_read_u16_at(newbbuf, rbuf_pos(newbbuf) - 1, &pointer))
                return NULL;
            rbuf_skip(newbbuf, 1);  // Skip the current one.
            int index = (0x3fff & pointer);
            newbbuf = rbuf_copy_at(newbbuf, index);
        } else {
            if (adddot) {
                namebuf[pos++] = '.';
            } else {
                adddot = true;
            }
            if (0 != rbuf_read_mem(newbbuf, label, labelsz)) return NULL;
            memcpy(namebuf + pos, label, labelsz);
            pos += labelsz;
        }
    }

    char *dname = malloc(pos + 1);
    if (dname == NULL) return NULL;
    memset(dname, 0, pos + 1);
    memcpy(dname, namebuf, pos);
    return dname;
}

static int encode_dns_domain_name(struct wbuf *wbuf, const char *buf) {
    const char *prev = buf;
    char *pos = strstr(buf, ".");
    for (; pos != NULL;) {
        unsigned char sz = pos - prev;
        if (0 != wbuf_write_u8(wbuf, sz)) return -1;
        if (0 != wbuf_write_mem(wbuf, prev, sz)) return -1;
        prev = pos + 1;
        pos = strstr(prev, ".");
    }
    unsigned char sz = strlen(prev);
    if (sz > 0) {
        if (0 != wbuf_write_u8(wbuf, sz)) return -1;
        if (0 != wbuf_write_mem(wbuf, prev, sz)) return -1;
    }
    return wbuf_write_u8(wbuf, 0);
}

static struct _hostshijacking_dns_question *decode_dns_question(
    struct rbuf *rbuf) {
    char *dname = decode_dns_domain_name(rbuf);
    if (NULL == dname) return NULL;
    struct _hostshijacking_dns_question *q =
        malloc(sizeof(struct _hostshijacking_dns_question));
    if (NULL == q) {
        free(dname);
        return NULL;
    }
    memset(q, 0, sizeof(*q));
    q->name = dname;

    if (0 != rbuf_read_u16(rbuf, &q->type)) {
        free(dname);
        free(q);
        return NULL;
    }
    if (0 != rbuf_read_u16(rbuf, &q->_class)) {
        free(dname);
        free(q);
        return NULL;
    }
    return q;
}

static int encode_dns_question(struct wbuf *wbuf,
                               const struct _hostshijacking_dns_question *q) {
    if (0 != encode_dns_domain_name(wbuf, q->name)) return -1;
    if (0 != wbuf_write_u16(wbuf, q->type)) return -1;
    if (0 != wbuf_write_u16(wbuf, q->_class)) return -1;
    return 0;
}

static struct _hostshijacking_dns_resource_record *decode_dns_resource_record(
    struct rbuf *rbuf) {
    char *dname = decode_dns_domain_name(rbuf);
    if (NULL == dname) return NULL;
    // Alloc later?
    struct _hostshijacking_dns_resource_record *rr =
        malloc(sizeof(struct _hostshijacking_dns_resource_record));
    if (NULL == rr) goto err_ret;
    memset(rr, 0, sizeof(*rr));
    rr->name = dname;
    rr->data.other = NULL;

    if (0 != rbuf_read_u16(rbuf, &rr->type)) goto err_ret;
    if (0 != rbuf_read_u16(rbuf, &rr->_class)) goto err_ret;
    if (0 != rbuf_read_u32(rbuf, &rr->ttl)) goto err_ret;
    if (0 != rbuf_read_u16(rbuf, &rr->rdlength)) goto err_ret;

    switch (rr->type) {
        case _HOSTSHIJACKING_DNS_TYPE_A:
            if (0 != rbuf_read_mem(rbuf, (char *)&rr->data.ipv4, 4))
                goto err_ret;
            break;
        case _HOSTSHIJACKING_DNS_TYPE_AAAA:
            if (0 != rbuf_read_mem(rbuf, (char *)rr->data.ipv6, 16))
                goto err_ret;
            break;
        default:
            rr->data.other = (char *)malloc(rr->rdlength);
            if (NULL == rr->data.other) goto err_ret;
            memset(rr->data.other, 0, sizeof(*(rr->data.other)));
            if (0 != rbuf_read_mem(rbuf, (char *)rr->data.other, rr->rdlength))
                goto err_ret;
            break;
    }

    return rr;
err_ret:
    free(dname);
    if (NULL != rr) {
        rr->name = NULL;
        if (rr->type != _HOSTSHIJACKING_DNS_TYPE_A &&
            rr->type != _HOSTSHIJACKING_DNS_TYPE_AAAA &&
            NULL != rr->data.other) {
            free(rr->data.other);
        }
        free(rr);
    }
    return NULL;
}

static int encode_dns_resource_record(
    struct wbuf *wbuf, const struct _hostshijacking_dns_resource_record *rr) {
    if (0 != encode_dns_domain_name(wbuf, rr->name)) return -1;
    if (0 != wbuf_write_u16(wbuf, rr->type)) return -1;
    if (0 != wbuf_write_u16(wbuf, rr->_class)) return -1;
    if (0 != wbuf_write_u32(wbuf, rr->ttl)) return -1;
    if (0 != wbuf_write_u16(wbuf, rr->rdlength)) return -1;

    switch (rr->type) {
        case _HOSTSHIJACKING_DNS_TYPE_A:
            if (0 != wbuf_write_mem(wbuf, (char *)&rr->data.ipv4, 4)) return -1;
            break;
        case _HOSTSHIJACKING_DNS_TYPE_AAAA:
            if (0 != wbuf_write_mem(wbuf, (char *)rr->data.ipv6, 16)) return -1;
            break;
        default:
            if (0 != wbuf_write_mem(wbuf, (char *)rr->data.other, rr->rdlength))
                return -1;
            break;
    }
    return 0;
}

static struct rbuf *rbuf_from(const char *data, int size) {
    struct rbuf *b = malloc(sizeof(struct rbuf));
    if (NULL == b) return NULL;
    memset(b, 0, sizeof(*b));
    b->data = data;
    b->pos = 0;
    b->size = size;
    return b;
}

static struct rbuf *rbuf_copy_at(struct rbuf *b, int index) {
    return rbuf_from(b->data + index, b->size);
}

static void rbuf_free(struct rbuf *b) {
    assert(NULL != b);
    b->data = NULL;
    b->size = -1;
    free(b);
    b = NULL;
}

static int rbuf_pos(struct rbuf *b) {
    assert(b != NULL);
    return b->pos;
}

static int rbuf_read_u8(struct rbuf *b, unsigned char *v) {
    assert(b != NULL);
    return rbuf_read_mem(b, (char *)v, sizeof(unsigned char));
}

static int rbuf_read_u16(struct rbuf *b, unsigned short *v) {
    assert(b != NULL);
    int r = rbuf_read_mem(b, (char *)v, sizeof(unsigned short));
    if (0 == r) *v = ntohs(*v);
    return r;
}

static int rbuf_read_u32(struct rbuf *b, unsigned int *v) {
    assert(b != NULL);
    int r = rbuf_read_mem(b, (char *)v, sizeof(unsigned int));
    if (0 == r) *v = ntohl(*v);
    return r;
}

static int rbuf_read_mem(struct rbuf *b, char *buf, unsigned int size) {
    int r = rbuf_read_mem_at(b, b->pos, buf, size);
    if (0 == r) {
        b->pos += size;
    }
    return r;
}

static int rbuf_read_u8_at(struct rbuf *b, unsigned int index,
                           unsigned char *v) {
    assert(b != NULL);
    return rbuf_read_mem_at(b, index, (char *)v, sizeof(unsigned char));
}

static int rbuf_read_u16_at(struct rbuf *b, unsigned int index,
                            unsigned short *v) {
    assert(b != NULL);
    int r = rbuf_read_mem_at(b, index, (char *)v, sizeof(unsigned short));
    if (0 == r) *v = ntohs(*v);
    return r;
}

static int rbuf_read_mem_at(struct rbuf *b, unsigned int index, char *buf,
                            unsigned int size) {
    assert(b != NULL);
    if (index + size > b->size) {
        return -1;
    }
    memcpy(buf, b->data + index, size);
    return 0;
}
static int rbuf_skip(struct rbuf *b, unsigned int size) {
    assert(b != NULL);
    if (b->pos + size > b->size) {
        return -1;
    }
    b->pos += size;
    return 0;
}

static struct wbuf *wbuf_from(char *data, int size) {
    struct wbuf *b = malloc(sizeof(struct wbuf));
    if (NULL == b) return NULL;
    memset(b, 0, sizeof(*b));
    b->data = data;
    b->pos = 0;
    b->size = size;
    return b;
}

static void wbuf_free(struct wbuf *b) {
    assert(NULL != b);
    b->data = NULL;
    b->size = -1;
    free(b);
    b = NULL;
}

static int wbuf_pos(struct wbuf *b) {
    assert(b != NULL);
    return b->pos;
}

static int wbuf_write_u8(struct wbuf *b, unsigned char v) {
    assert(b != NULL);
    return wbuf_write_mem(b, (char *)&v, sizeof(unsigned char));
}

static int wbuf_write_u16(struct wbuf *b, unsigned short v) {
    assert(b != NULL);
    v = htons(v);
    return wbuf_write_mem(b, (char *)&v, sizeof(unsigned short));
}

static int wbuf_write_u32(struct wbuf *b, unsigned int v) {
    assert(b != NULL);
    v = htonl(v);
    return wbuf_write_mem(b, (char *)&v, sizeof(unsigned int));
}

static int wbuf_write_mem(struct wbuf *b, const char *buf, unsigned int size) {
    int r = wbuf_write_mem_at(b, b->pos, buf, size);
    if (0 == r) {
        b->pos += size;
    }
    return r;
}

static int wbuf_write_mem_at(struct wbuf *b, unsigned int index,
                             const char *buf, unsigned int size) {
    assert(b != NULL);
    if (index + size > b->size) {
        return -1;
    }
    memcpy(b->data + index, buf, size);
    return 0;
}

#ifdef HA_DNS_TEST

static void test_dns_hdr() {
    char buf[1024];
    struct wbuf *wbbuf = wbuf_from(buf, 1024);
    struct _hostshijacking_dns_hdr hdr = {
        .id = 23,
        .qr = 1,
        .opcode = 0,
        .aa = 0,
        .tc = 0,
        .rd = 0,
        .ra = 0,
        .z = 0,
        .rcode = 0,
        .qdcount = 0,
        .ancount = 1,
        .nscount = 0,
        .arcount = 0,
    };
    assert(-1 != encode_dns_hdr(wbbuf, hdr));

    struct _hostshijacking_dns_hdr actual_hdr;
    struct rbuf *rbbuf = rbuf_from(wbbuf->data, wbuf_pos(wbbuf));
    wbuf_free(wbbuf);
    assert(-1 != decode_dns_hdr(rbbuf, &actual_hdr));
    assert(hdr.id == actual_hdr.id);
    assert(hdr.qr == actual_hdr.qr);
    assert(hdr.opcode == actual_hdr.opcode);
    assert(hdr.aa == actual_hdr.aa);
    assert(hdr.tc == actual_hdr.tc);
    assert(hdr.rd == actual_hdr.rd);
    assert(hdr.ra == actual_hdr.ra);
    assert(hdr.z == actual_hdr.z);
    assert(hdr.rcode == actual_hdr.rcode);
    assert(hdr.qdcount == actual_hdr.qdcount);
    assert(hdr.ancount == actual_hdr.ancount);
    assert(hdr.nscount == actual_hdr.nscount);
    assert(hdr.arcount == actual_hdr.arcount);
    rbuf_free(rbbuf);
}

void test_dns_encoding() {
    char buf[1024];
    struct _hostshijacking_dns_hdr hdr = {
        .id = 23,
        .qr = 1,
        .opcode = 0,
        .aa = 0,
        .tc = 0,
        .rd = 0,
        .ra = 0,
        .z = 0,
        .rcode = 0,
        .qdcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };
    struct _hostshijacking_dns_reply reply = {
        .hdr = hdr,
        .qds = NULL,
        .ans = NULL,
        .nss = NULL,
        .ars = NULL,
    };
    assert(0 != _hostshijacking_encode_dns_reply(&reply, buf, 1024));
    unsigned int pos;
    struct _hostshijacking_dns_reply *actual =
        _hostshijacking_decode_dns_reply(buf, 1024, &pos);
    assert(NULL == actual);
    /* free_dns_reply(actual); */
}

int main(int argc, char *argv[]) {
    test_dns_hdr();
    test_dns_encoding();
    return 0;
}

#endif
