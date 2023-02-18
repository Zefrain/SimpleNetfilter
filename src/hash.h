/**
 *   @file     hash.h
 *   @date     2020-03-11
 *   @author   whiothes <whiothes81@gmail.com>
 *   @version  1.0
 *   @brief    hash APIs
 */

#ifndef HASH_H
#define HASH_H

#include <linux/list_nulls.h>
#include <linux/mm.h>

#include "file.h"

#define HASH_MASK_BITS 0x3 /* & 0011 */
#define HOST_HASH_SIZE 4

typedef struct host_hash_s host_hash_t;
struct host_hash_s {
    struct hlist_nulls_node hnode;
    char*                   data; /* host list */
};

extern struct hlist_nulls_head* hhash_head;

void*                    host_hash_alloc(u_int* sizep, int nulls);
bool                     host_hash_check_insert(const char* buf);
void                     host_hash_destroy(void);
struct hlist_nulls_node* host_hash_find(const char* buf, const int len);

u_int scale_hash(const void* buf, int len);



#endif /* HASH_H */
