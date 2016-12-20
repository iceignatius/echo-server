#include <stdlib.h>
#include <stdio.h>
#include <threads.h>
#include <unistd.h>
#include "epoll_encap.h"

//------------------------------------------------------------------------------
void epoll_encap_init(epoll_encap_t *self)
{
    /**
     * @memberof epoll_encap_t
     * @brief Constructor.
     */
    self->epfd = -1;
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
static
int event_dispatcher(struct epoll_event *data)
{
    uint32_t events = data->events;
    epoll_encap_callbacks_t *callbacks = data->data.ptr;

    if( !atomic_fetch_and(&callbacks->calling_count, 1) )
    {
        if(( callbacks->on_read )&&( events & ( EPOLLIN | EPOLLPRI ) ))
            callbacks->on_read(callbacks->userarg);

        if(( callbacks->on_write )&&( events & EPOLLOUT ))
            callbacks->on_write(callbacks->userarg);

        if(( callbacks->on_error )&&( events & ( EPOLLERR | EPOLLHUP ) ))
            callbacks->on_error(callbacks->userarg);
    }
    atomic_fetch_sub(&callbacks->calling_count, 1);

    free(data);
    return 0;
}
//------------------------------------------------------------------------------
void epoll_encap_process_events(epoll_encap_t *self, unsigned timeout)
{
    /**
     * @memberof epoll_encap_t
     * @brief Check and process all events.
     *
     * @param self    Object instance.
     * @param timeout The time to wait events in milliseconds.
     */
    if( self->epfd < 0 ) return;

    struct epoll_event list[1024];
    static const int max_count = sizeof(list)/sizeof(list[0]);
    int count = epoll_wait(self->epfd, list, max_count, timeout);
    if( count <= 0 ) return;

    for(int i=0; i<count; ++i)
    {
        struct epoll_event *item = malloc(sizeof(struct epoll_event));
        if( !item )
        {
            fputs("ERROR: Cannot allocate more memory!\n", stderr);
            abort();
        }

        *item = list[i];

        thrd_t thrd;
        if( thrd_success != thrd_create(&thrd, (int(*)(void*)) event_dispatcher, item) )
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
}
//------------------------------------------------------------------------------
