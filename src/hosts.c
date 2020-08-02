#include "hosts.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// N.B. The table implementation was copy and modified from:
//        https://github.com/drh/cii/blob/master/src/table.c
struct __table {
    int size;
    int (*cmp)(const char *x, const char *y);
    unsigned (*hash)(const char *key);
    int length;
    struct binding {
        struct binding *link;
        char *key;
        void *value;
    } * *buckets;
};

struct __table *parse_hosts(const char *filename);
struct __table *table_new(int hint, unsigned hash(const char *key));
void *table_get(struct __table *table, char *key);
void *table_put(struct __table *table, char *key, void *value);
void table_free(struct __table *table);

static int cmpkey(const char *x, const char *y) { return strcmp(x, y); }

static unsigned hashkey(const char *key) {
    // Ref: https://stackoverflow.com/a/7666577/2996656
    unsigned long hash = 5381;
    int c;

    while (0 != (c = *key++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

_hostshijacking_table *_hostshijacking_parse_hosts(const char *filename) {
    return (_hostshijacking_table *)parse_hosts(filename);
}

void *_hostshijacking_table_get(_hostshijacking_table *table, char *key) {
    return table_get((struct __table *)table, key);
}

void *_hostshijacking_table_put(_hostshijacking_table *table, char *key,
                                void *value) {
    return table_put((struct __table *)table, key, value);
}

struct __table *parse_hosts(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (NULL == fp) return NULL;
    struct __table *table = table_new(64, NULL);
    if (NULL == table) goto err_ret;

    char ipb[39], domainb[253];
    for (; EOF != fscanf(fp, "%s %s", ipb, domainb);) {
        int ip_len = strlen(ipb);
        char *ip = (char *)malloc(ip_len + 1);
        if (NULL == ip) goto err_ret;
        memset(ip, 0, ip_len + 1);
        memcpy(ip, ipb, ip_len);
        int domain_len = strlen(domainb);
        char *domain = (char *)malloc(domain_len + 1);
        if (NULL == domain) goto err_ret;
        memset(domain, 0, domain_len);
        memcpy(domain, domainb, domain_len);
        table_put(table, domain, ip);
    }
    return table;

err_ret:
    if (fp != NULL) fclose(fp);
    if (table != NULL) table_free(table);
    return NULL;
}

struct __table *table_new(int hint, unsigned hash(const char *key)) {
    struct __table *table;
    int i;
    static int primes[] = {31, 61, 121, 509, 1021, INT_MAX};
    assert(hint >= 0);
    for (i = 1; primes[i] < hint; i++)
        ;
    table = (struct __table *)malloc(sizeof(*table) +
                                     primes[i - 1] * sizeof(table->buckets[0]));
    table->size = primes[i - 1];
    table->cmp = cmpkey;
    table->hash = hash ? hash : hashkey;
    table->buckets = (struct binding **)(table + 1);
    for (i = 0; i < table->size; i++) table->buckets[i] = NULL;
    table->length = 0;
    return table;
}

void *table_get(struct __table *table, char *key) {
    assert(table);
    assert(key);

    int i = (*table->hash)(key) % table->size;
    struct binding *p;
    for (p = table->buckets[i]; p != NULL; p = p->link)
        if ((*table->cmp)(key, p->key) == 0) break;
    return p ? p->value : NULL;
}

void *table_put(struct __table *table, char *key, void *value) {
    assert(table);
    assert(key);
    int i = (*table->hash)(key) % table->size;
    struct binding *p;
    for (p = table->buckets[i]; p; p = p->link)
        if ((*table->cmp)(key, p->key) == 0) break;

    void *prev;
    if (p == NULL) {
        p = (struct binding *)malloc(sizeof(*p));
        p->key = key;
        p->link = table->buckets[i];
        table->buckets[i] = p;
        table->length++;
        prev = NULL;
    } else
        prev = p->value;
    p->value = value;
    return prev;
}

void table_free(struct __table *table) {
    assert(table);
    if (table->length > 0) {
        int i;
        struct binding *p, *q;
        for (i = 0; i < table->size; i++)
            for (p = table->buckets[i]; p; p = q) {
                q = p->link;
                // XXX(damnever): free key and values.
                free(p->key);
                free(p->value);
                free(p);
            }
    }
    free(table);
}
