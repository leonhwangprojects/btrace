#ifndef __BPF_MAP_HELPERS_H_
#define __BPF_MAP_HELPERS_H_

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "errno.h"

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
    void *val;
    long err;

    val = bpf_map_lookup_elem(map, key);
    if (val)
        return val;

    err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
    if (err && err != -EEXIST)
        return 0;

    return bpf_map_lookup_elem(map, key);
}

static __always_inline void *
bpf_map_lookup_and_delete(void *map, const void *key)
{
    void *val = bpf_map_lookup_elem(map, key);
    if (val)
        bpf_map_delete_elem(map, key);

    return val;
}

#endif // __BPF_MAP_HELPERS_H_
