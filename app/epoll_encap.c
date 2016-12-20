#include <stdlib.h>
#include <stdio.h>
#include <threads.h>
#include <unistd.h>
#include <gen/systime.h>
#include "epoll_encap.h"

typedef struct event_dispatch_data_t
{
    struct epoll_event  data;
    atomic_int         *processing_count;
} event_dispatch_data_t;

//------------------------------------------------------------------------------
static
event_dispatch_data_t* event_dispatch_data_create(struct epoll_event *data,
                                                  atomic_int         *processing_count)
{
    event_dispatch_data_t *inst = malloc(sizeof(event_dispatch_data_t));
    if( !inst )
    {
        fputs("ERROR: Cannot allocate more memory!\n", stderr);
        abort();
    }

    inst->data = *data;
    inst->processing_count = processing_count;

    return inst;
}
//------------------------------------------------------------------------------
static
void event_dispatch_data_release(event_dispatch_data_t *self)
{
    free(self);
}
//------------------------------------------------------------------------------
static
int event_dispatch_proc(event_dispatch_data_t *self)
{
    atomic_fetch_add(self->processing_count, 1);
    {
        uint32_t events = self->data.events;
        epoll_encap_callbacks_t *callbacks = self->data.data.ptr;

        if( !atomic_fetch_add(&callbacks->calling_count, 1) )
        {
            if(( callbacks->on_read )&&( events & ( EPOLLIN | EPOLLPRI ) ))
                callbacks->on_read(callbacks->userarg);

            if(( callbacks->on_write )&&( events & EPOLLOUT ))
                callbacks->on_write(callbacks->userarg);

            if(( callbacks->on_error )&&( events & ( EPOLLERR | EPOLLHUP ) ))
                callbacks->on_error(callbacks->userarg);
        }
        atomic_fetch_sub(&callbacks->calling_count, 1);
    }
    atomic_fetch_sub(self->processing_count, 1);

    event_dispatch_data_release(self);
    return 0;
}
//------------------------------------------------------------------------------
void epoll_encap_init(epoll_encap_t *self)
{
    /**
     * @memberof epoll_encap_t
     * @brief Constructor.
     */
    self->epfd = -1;
    atomic_init(&self->processing_count, 0);
}
//------------------------------------------------------------------------------
void epoll_encap_deinit(epoll_encap_t *self)
{
    /**
     * @memberof epoll_encap_t
     * @brief Destructor.
     */
    epoll_encap_clear(self);
}
//------------------------------------------------------------------------------
void epoll_encap_clear(epoll_encap_t *self)
{
    /**
     * @memberof epoll_encap_t
     * @brief Clear all events.
     */
    if( self->epfd < 0 ) return;

    if( close(self->epfd) )
    {
        fputs("ERROR: Cannot close epoll handler!\n", stderr);
        abort();
    }

    self->epfd = -1;
}
//------------------------------------------------------------------------------
bool epoll_encap_add(epoll_encap_t           *self,
                     int                      fd,
                     uint32_t                 events,
                     epoll_encap_callbacks_t *callbacks)
{
    /**
     * @memberof epoll_encap_t
     * @brief Add an object to watch list.
     *
     * @param self      Object instance.
     * @param fd        The file descriptor to be watched.
     * @param events    Event flags that be defined in original epoll.
     * @param callbacks the callback functions that will be called on event,
     *                  and this data of structure must be available during
     *                  the observation period.
     * @return TRUE if success; and FALSE if failed.
     */
    bool res = false;
    do
    {
        if( self->epfd < 0 )
            self->epfd = epoll_create1(0);
        if( self->epfd < 0 )
            break;

        atomic_init(&callbacks->calling_count, 0);

        struct epoll_event event_data;
        event_data.data.ptr = callbacks;
        event_data.events   = events;

        if( epoll_ctl(self->epfd, EPOLL_CTL_ADD, fd, &event_data) )
            break;

        res = true;
    } while(false);

    return res;
}
//------------------------------------------------------------------------------
bool epoll_encap_modify(epoll_encap_t           *self,
                        int                      fd,
                        uint32_t                 events,
                        epoll_encap_callbacks_t *callbacks)
{
    /**
     * @memberof epoll_encap_t
     * @brief Modify events of one object in watch list.
     *
     * @param self      Object instance.
     * @param fd        The file descriptor to be watched.
     * @param events    Event flags that be defined in original epoll.
     * @param callbacks the callback functions that will be called on event,
     *                  and this data of structure must be available during
     *                  the observation period.
     * @return TRUE if success; and FALSE if failed.
     */
    bool res = false;
    do
    {
        if( self->epfd < 0 )
            self->epfd = epoll_create1(0);
        if( self->epfd < 0 )
            break;

        struct epoll_event event_data;
        event_data.data.ptr = callbacks;
        event_data.events   = events;

        if( epoll_ctl(self->epfd, EPOLL_CTL_MOD, fd, &event_data) )
            break;

        res = true;
    } while(false);

    return res;
}
//------------------------------------------------------------------------------
void epoll_encap_remove(epoll_encap_t *self, int fd)
{
    /**
     * @memberof epoll_encap_t
     * @brief Remove an object from watch list by file descriptor.
     */
    if( self->epfd < 0 ) return;

    epoll_ctl(self->epfd, EPOLL_CTL_DEL, fd, NULL);
}
//------------------------------------------------------------------------------
int epoll_encap_process_events(epoll_encap_t *self, unsigned timeout)
{
    /**
     * @memberof epoll_encap_t
     * @brief Check and process all events.
     *
     * @param self    Object instance.
     * @param timeout The time to wait events in milliseconds.
     */
    if( self->epfd < 0 ) return 0;

    struct epoll_event list[1024];
    static const int max_count = sizeof(list)/sizeof(list[0]);
    int count = epoll_wait(self->epfd, list, max_count, timeout);

    for(int i=0; i<count; ++i)
    {
        event_dispatch_data_t *data = event_dispatch_data_create(&list[i],
                                                                 &self->processing_count);

        thrd_t thrd;
        if( thrd_success != thrd_create(&thrd, (int(*)(void*)) event_dispatch_proc, data) )
        {
            fputs("ERROR: Cannot create thread!\n", stderr);
            abort();
        }

        if( thrd_success != thrd_detach(thrd) )
        {
            fputs("ERROR: Cannot detach thread!\n", stderr);
            abort();
        }
    }

    return count;
}
//------------------------------------------------------------------------------
void epoll_encap_wait_all_events(epoll_encap_t *self)
{
    /**
     * @memberof epoll_encap_t
     * @brief Block until all event process are finished.
     */
    while( atomic_load(&self->processing_count) )
        systime_sleep_awhile();
}
//------------------------------------------------------------------------------
