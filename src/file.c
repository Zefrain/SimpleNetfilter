#include "file.h"

#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>

#include "hash.h"

struct file* file_open(const char* path, int flags, int rights) {
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int          err = 0;

    oldfs = get_fs();
    set_fs(get_ds());

    filp = filp_open(path, flags, rights);
    set_fs(oldfs);

    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file* file) { filp_close(file, NULL); }

/* read line from file */
u_char* read_line(struct file* file, u_char* buf, int len) {
    int          ret;
    int          i = 0;
    mm_segment_t fs;
    struct file* fp = file;

    fs = get_fs();
    set_fs(KERNEL_DS);
    ret = fp->f_op->read(fp, buf, len, &(fp->f_pos));
    set_fs(fs);

    if (ret <= 0) return NULL;

    while (buf[i++] != '\n' && i < ret)
        ;

    if (i < ret) {
        fp->f_pos += i - ret;
    }

    if (i < len) {
        buf[i] = 0;
    }

    return buf;
}

u_char* str_trailing(u_char* buf) {
    int tail = strlen(buf) - 1;

    while (1) {
        if (buf[tail] == '\n' || buf[tail] == ' ' || buf[tail] == '\t') {
            buf[tail] = 0;
            tail--;
        } else {
            return buf;
        }
    }
}

int get_hostlist(void) {
    struct file* fp;
    u_char       buf[MAX_HOST_STRLEN];
    u_int        sizep;
    int          num;

    sizep = HOST_HASH_SIZE;
    memset(buf, 0, sizeof(buf));
    hhash_head = host_hash_alloc(&sizep, 1);
    if (!hhash_head) {
        printk(KERN_INFO "allocate memory error");
        return -1;
    }

    fp = file_open(BLACK_LIST_FILE, O_RDONLY, 0);

    num = 0;
    while (read_line(fp, buf, sizeof(buf))) {
        str_trailing(buf);
        if (buf[0]) {
            if (host_hash_check_insert(buf)) {
                ++num;
            }
        }
    }

    file_close(fp);

    printk(KERN_INFO "Host black-list number: %d", num);

    return num;
}
