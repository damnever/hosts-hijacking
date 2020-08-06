#ifndef _HOSTSHIJACKING_HOSTS_H_
#define _HOSTSHIJACKING_HOSTS_H_

typedef struct __table _hostshijacking_table;

_hostshijacking_table *_hostshijacking_parse_hosts(const char *filename);
void *_hostshijacking_table_get(_hostshijacking_table *table, char *key);
// void _hostshijacking_table_free(_hostshijacking_table *table);
#endif
