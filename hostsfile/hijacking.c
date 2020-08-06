#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct _hostshijacking_list {
    struct _hostshijacking_list *prev;
    struct _hostshijacking_list *next;
    int fd;
    int ridx;
};

struct _hostshijacking_hosts {
    char *buf;
    size_t sz;
};

pthread_mutex_t _hosts_lock;
__thread struct _hostshijacking_list _fds = {
    .prev = NULL,
    .next = NULL,
    .fd = -1,
    .ridx = -1,
};
pthread_mutex_t _hosts_lock;
static struct _hostshijacking_hosts *_hosts = NULL;

static struct _hostshijacking_hosts *_init_hosts();
static struct _hostshijacking_list *_search_fd(int fd);
static struct _hostshijacking_list *_add_fd(int fd);
static void _remove_fd(int fd);

int open(const char *pathname, int flags, ...) {
    int (*origin_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    int fd;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        int mode = va_arg(args, int);
        va_end(args);
        fd = (*origin_open)(pathname, flags, mode);
    } else {
        fd = (*origin_open)(pathname, flags);
    }
    if (fd < 0) return fd;
    if (0 != strcmp("/etc/hosts", pathname)) {
        return fd;
    }

    struct _hostshijacking_hosts *hosts = _init_hosts();
    if (NULL != hosts) _add_fd(fd);
    return fd;
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    int (*origin_openat)(int, const char *, int, ...) =
        dlsym(RTLD_NEXT, "openat");
    int fd;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        int mode = va_arg(args, int);
        va_end(args);
        fd = (*origin_openat)(dirfd, pathname, flags, mode);
    } else {
        fd = (*origin_openat)(dirfd, pathname, flags);
    }
    if (fd < 0) return fd;
    if (0 != strcmp("/etc/hosts", pathname)) {
        return fd;
    }
    struct _hostshijacking_hosts *hosts = _init_hosts();
    if (NULL != hosts) _add_fd(fd);
    return fd;
}

ssize_t read(int fd, void *buf, size_t count) {
    ssize_t (*origin_read)(int, void *, size_t) = dlsym(RTLD_NEXT, "read");
    ssize_t sz = (*origin_read)(fd, buf, count);
    if (sz != 0) return sz;

    struct _hostshijacking_hosts *hosts = _init_hosts();
    if (NULL == hosts) return sz;
    struct _hostshijacking_list *node = _search_fd(fd);
    if (NULL == node) return sz;

    int remain = hosts->sz - node->ridx;
    if (remain == 0) return 0;
    if (count > remain) {
        count = remain;
    }
    memcpy(buf, hosts->buf + node->ridx, count);
    node->ridx += count;
    return count;
}

int close(int fd) {
    int (*origin_close)(int) = dlsym(RTLD_NEXT, "close");
    int code = (*origin_close)(fd);
    _remove_fd(fd);
    return code;
}

static struct _hostshijacking_hosts *_init_hosts() {
    const char *filename = getenv("HOSTS_HIJACKING");
    if (NULL == filename) return NULL;
    pthread_mutex_lock(&_hosts_lock);
    if (NULL != _hosts) {
        pthread_mutex_unlock(&_hosts_lock);
        return _hosts;
    }

    int (*origin_open)(const char *, int) = dlsym(RTLD_NEXT, "open");
    int (*origin_close)(int) = dlsym(RTLD_NEXT, "close");
    int fd = (*origin_open)(filename, O_RDONLY);
    if (fd < 0) {
        pthread_mutex_unlock(&_hosts_lock);
        return NULL;
    }

    _hosts = malloc(sizeof(*_hosts));
    memset(_hosts, 0, sizeof(*_hosts));
    _hosts->buf = NULL;

    int allocated = 0;
    ssize_t (*origin_read)(int, void *, size_t) = dlsym(RTLD_NEXT, "read");
    char tmpbuf[4096];
    ssize_t sz = (*origin_read)(fd, tmpbuf, 4096);
    for (; sz > 0;) {
        if (sz > allocated - _hosts->sz) {
            allocated = (sz + _hosts->sz) * 2;
            char *buf = malloc(allocated);
            if (NULL != _hosts->buf) {
                free(_hosts->buf);
            }
            _hosts->buf = buf;
        }
        memcpy(_hosts->buf + _hosts->sz, tmpbuf, sz);
        _hosts->sz += sz;
        sz = (*origin_read)(fd, tmpbuf, 4096);
    }

    (*origin_close)(fd);
    if (sz < 0) {
        if (allocated > 0) {
            free(_hosts->buf);
        }
        _hosts->buf = NULL;
        free(_hosts);
        pthread_mutex_unlock(&_hosts_lock);
        return NULL;
    }
    pthread_mutex_unlock(&_hosts_lock);
    return _hosts;
}

static struct _hostshijacking_list *_search_fd(int fd) {
    struct _hostshijacking_list *node = _fds.prev;
    for (; node != NULL; node = node->next) {
        if (node->fd == fd) break;
    }
    if (node == NULL || node->fd != fd) return NULL;
    return node;
}

static struct _hostshijacking_list *_add_fd(int fd) {
    struct _hostshijacking_list *node = _search_fd(fd);
    if (NULL != node) return node;

    node = malloc(sizeof(struct _hostshijacking_list));
    node->fd = fd;
    node->ridx = 0;
    node->next = NULL;
    node->prev = _fds.next;
    if (_fds.next == NULL) {
        _fds.next = node;
        _fds.prev = node;
    } else {
        _fds.next->next = node;
        _fds.next = node;
    }
    return node;
}

static void _remove_fd(int fd) {
    struct _hostshijacking_list *node = _search_fd(fd);
    if (NULL == node) return;
    if (node->prev == NULL) {  // First one.
        _fds.prev = NULL;
        _fds.next = NULL;
    } else {
        node->prev->next = node->next;
        if (node->next != NULL) {
            node->next->prev = node->prev;
        } else {  // Last one.
            _fds.next = node->prev;
        }
    }
    free(node);
}
