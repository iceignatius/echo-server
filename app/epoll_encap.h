/*
 * Encapsulation of Linux epoll.
 */
#ifndef _EPOLL_ENCAP_H_
#define _EPOLL_ENCAP_H_

#include <stdbool.h>
#include <stdatomic.h>
#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callbacks.
 */
typedef struct epoll_encap_callbacks_t
{
    void *userarg;  // User defined argument that will be passed to callbacks.

    // Functions will be called in a separated thread,
    // But only one function will be execute at one time.
    void(*on_read )(void *userarg);
    void(*on_write)(void *userarg);
    void(*on_error)(void *userarg);

    atomic_int calling_count;  // Internal usage.

} epoll_encap_callbacks_t;

/**
 * @class epoll_encap_t
 * @brief Object encapsulation of epoll.
 */
typedef struct epoll_encap_t
{
    int epfd;
    atomic_int processing_count;
} epoll_encap_t;

void epoll_encap_init  (epoll_encap_t *self);
void epoll_encap_deinit(epoll_encap_t *self);

void epoll_encap_clear(epoll_encap_t *self);
bool epoll_encap_add(epoll_encap_t           *self,
                     int                      fd,
                     uint32_t                 events,
                     epoll_encap_callbacks_t *callbacks);
bool epoll_encap_modify(epoll_encap_t           *self,
                        int                      fd,
                        uint32_t                 events,
                        epoll_encap_callbacks_t *callbacks);
void epoll_encap_remove(epoll_encap_t *self, int fd);

void epoll_encap_process_events (epoll_encap_t *self, unsigned timeout);
void epoll_encap_wait_all_events(epoll_encap_t *self);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
