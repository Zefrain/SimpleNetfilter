#include "hash.h"

#include "file.h"

struct hlist_nulls_head* hhash_head;

static uint64_t MurmurHash64A(const void* key, int len, u_int seed);

void* host_hash_alloc(u_int* sizep, int nulls) {
    struct hlist_nulls_head* head;
    int                      i = 0;

    if (*sizep > (UINT_MAX / sizeof(struct hlist_nulls_head))) {
        return NULL;
    }

    BUILD_BUG_ON(sizeof(struct hlist_nulls_head) != sizeof(struct hlist_head));
    head = kvmalloc_array(*sizep, sizeof(struct hlist_nulls_head),
                          GFP_KERNEL | __GFP_ZERO);

    if (head && nulls) {
        for (i = 0; i < HOST_HASH_SIZE; i++) {
            INIT_HLIST_NULLS_HEAD(&head[i], i);
        }
    }
    return head;
}

bool host_hash_check_insert(const char* buf) {
    host_hash_t*             tpos;
    struct hlist_nulls_node* pos;
    int                      hash = 0;

    hash = scale_hash(buf, strlen(buf));

    pos = host_hash_find(buf, strlen(buf));
    if (pos != NULL) {
        return false;
    }

    tpos       = kvmalloc(sizeof(host_hash_t), GFP_KERNEL);
    tpos->data = kvmalloc(strlen(buf) + 1, GFP_KERNEL);
    strcpy(tpos->data, buf);

    hlist_nulls_add_head(&tpos->hnode, &hhash_head[hash]);

    return true;
}

struct hlist_nulls_node* host_hash_find(const char* buf, const int len) {
    host_hash_t*             tpos;
    struct hlist_nulls_node* pos;
    int                      hash;

    hash = scale_hash(buf, len);

    hlist_nulls_for_each_entry(tpos, pos, &hhash_head[hash], hnode) {
        if (strcmp(tpos->data, buf) == 0) {
            return pos;
        }
    }

    return NULL;
}

void host_hash_destroy(void) {
    int                      i = 0;
    host_hash_t*             tpos;
    struct hlist_nulls_node* pos;
    struct hlist_nulls_node  tmp;

    for (i = 0; i < HOST_HASH_SIZE; ++i) {
        hlist_nulls_for_each_entry(tpos, pos, &hhash_head[i], hnode) {
            tmp.next = pos->next;
            hlist_nulls_del(pos);
            pos = &tmp;

            kvfree(tpos->data);
            kvfree(tpos);
        }
    }

    kvfree(hhash_head);
}

u_int scale_hash(const void* buf, int len) {
    return MurmurHash64A(buf, strlen(buf), 0xadc83b19ULL) & HASH_MASK_BITS;
}

static uint64_t MurmurHash64A(const void* key, int len, u_int seed) {
    const uint64_t m    = 0xc6a4a7935bd1e995;
    const int      r    = 47;
    uint64_t       h    = seed ^ (len * m);
    const uint8_t* data = (const uint8_t*)key;
    const uint8_t* end  = data + (len - (len & 7));

    while (data != end) {
        uint64_t k;

#if defined(__LITTLE_ENDIAN_BITFIELD)
#ifdef USE_ALIGNED_ACCESS
        memcpy(&k, data, sizeof(uint64_t));
#else
        k = *((uint64_t*)data);
#endif
#else
        k = (uint64_t)data[0];
        k |= (uint64_t)data[1] << 8;
        k |= (uint64_t)data[2] << 16;
        k |= (uint64_t)data[3] << 24;
        k |= (uint64_t)data[4] << 32;
        k |= (uint64_t)data[5] << 40;
        k |= (uint64_t)data[6] << 48;
        k |= (uint64_t)data[7] << 56;
#endif

        k *= m;
        k ^= k >> r;
        k *= m;
        h ^= k;
        h *= m;
        data += 8;
    }

    switch (len & 7) {
        case 7:
            h ^= (uint64_t)data[6] << 48; /* fall-thru */
        case 6:
            h ^= (uint64_t)data[5] << 40; /* fall-thru */
        case 5:
            h ^= (uint64_t)data[4] << 32; /* fall-thru */
        case 4:
            h ^= (uint64_t)data[3] << 24; /* fall-thru */
        case 3:
            h ^= (uint64_t)data[2] << 16; /* fall-thru */
        case 2:
            h ^= (uint64_t)data[1] << 8; /* fall-thru */
        case 1:
            h ^= (uint64_t)data[0];
            h *= m; /* fall-thru */
    };

    h ^= h >> r;
    h *= m;
    h ^= h >> r;
    return h;
}
