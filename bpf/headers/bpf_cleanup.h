// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Leon Hwang. */

#ifndef __BPF_CLEANUP_H_
#define __BPF_CLEANUP_H_

#include "bpf_helpers.h"

#ifndef __cleanup
#define __cleanup(fn) __attribute__((cleanup(fn)))
#endif

struct guard_spinlock_t {
    struct bpf_spin_lock *lock;
};

void
guard_spinlock_destructor(struct guard_spinlock_t *guard)
{
    bpf_spin_unlock(guard->lock);
}

#define guard_spinlock_constructor(lock)        \
({                                              \
    struct guard_spinlock_t guard = { lock };   \
    bpf_spin_lock(lock);                        \
    guard;                                      \
})

#define guard_spinlock(lock)                                            \
    struct guard_spinlock_t var __cleanup(guard_spinlock_destructor) =  \
        guard_spinlock_constructor(lock)

struct guard_ringbuf {
    void *data;
    int *err;
};

void
guard_ringbuf_destructor(struct guard_ringbuf *guard)
{
    if (!guard->data)
        return;

    if (*guard->err)
        bpf_ringbuf_discard(guard->data, 0);
    else
        bpf_ringbuf_submit(guard->data, 0);
}

#define guard_ringbuf_constructor(ringbuf, size, _err)  \
({                                                      \
    struct guard_ringbuf guard = { };                   \
    guard.err = _err;                                   \
    guard.data = bpf_ringbuf_reserve(ringbuf, size, 0); \
    guard;                                              \
})

#define guard_ringbuf(_ringbuf, _data, _err)                        \
    struct guard_ringbuf _g __cleanup(guard_ringbuf_destructor) =   \
        guard_ringbuf_constructor(_ringbuf, sizeof(*_data), _err);  \
    _data = (typeof(_data)) _g.data;

#endif // __BPF_CLEANUP_H_
