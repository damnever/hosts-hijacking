#include <arpa/inet.h>
#include <assert.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "dns.h"
#include "hosts.h"

// FIXME(damnever): Cache it and make it thread safe.
// static _hostshijacking_table *__hosts = NULL;

_hostshijacking_table *__hosts_table() {
    /* if (NULL != __hosts) return __hosts; */
    const char *filename = getenv("HOSTS_HIJACKING");
    if (NULL == filename) return NULL;
    _hostshijacking_table *hosts = _hostshijacking_parse_hosts(filename);
    return hosts;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    ssize_t *(*origin_recvfrom)(int, void *, size_t, int, struct sockaddr *,
                                socklen_t *);
    origin_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    ssize_t bufsz =
        (ssize_t)(*origin_recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
    if (-1 == bufsz) return bufsz;

    _hostshijacking_table *hosts = __hosts_table();
    if (NULL == hosts) return bufsz;  // Skip.

    unsigned int pos;
    struct _hostshijacking_dns_reply *reply =
        _hostshijacking_decode_dns_reply(buf, bufsz, &pos);
    if (NULL == reply) return bufsz;  // Skip.
    if (0 == reply->hdr.qdcount) {    // Skip.
        _hostshijacking_free_dns_reply(reply);
        return bufsz;
    }

    const char *ip = _hostshijacking_table_get(hosts, reply->qds[0]->name);
    if (NULL == ip) {  // Skip.
        _hostshijacking_free_dns_reply(reply);
        return bufsz;
    }

    char addrbuf[16];
    for (int i = 0; i < reply->hdr.ancount; i++) {
        if (reply->ans[i]->type != _HOSTSHIJACKING_DNS_TYPE_A &&
            reply->ans[i]->type != _HOSTSHIJACKING_DNS_TYPE_AAAA) {
            continue;
        }
        if (1 == inet_pton(AF_INET, ip, addrbuf)) {
            reply->ans[i]->type = _HOSTSHIJACKING_DNS_TYPE_A;
            reply->ans[i]->rdlength = 4;
            memcpy(&(reply->ans[i]->data.ipv4), addrbuf, 4);
        } else if (1 == inet_pton(AF_INET6, ip, addrbuf)) {
            reply->ans[i]->type = _HOSTSHIJACKING_DNS_TYPE_AAAA;
            reply->ans[i]->rdlength = 16;
            memcpy(reply->ans[i]->data.ipv6, addrbuf, 16);
        } else {
            _hostshijacking_free_dns_reply(reply);
            return -1;
        }
    }

    int newpos = _hostshijacking_encode_dns_reply(reply, buf, len);
    _hostshijacking_free_dns_reply(reply);
    if (-1 == newpos) {
        return -1;
    }
    return newpos;
}
