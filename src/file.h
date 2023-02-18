/**
 *   @file     proc_file.h
 *   @date     2020-03-08
 *   @author   whiothes <whiothes81@gmail.com>
 *   @version  1.0
 *   @brief    process host blacklist file
 */

#ifndef PROC_FILE_H
#define PROC_FILE_H

#include <linux/list.h>
#include <linux/string.h>

#define BLACK_LIST_FILE "/etc/simple_nf.d/hostlist.conf"
#define MAX_HOST_STRLEN 32

struct file* file_open(const char* path, int flags, int rights);
void         file_close(struct file* file);
u_char*      read_line(struct file* file, u_char* buf, int len);
u_char*      str_trailing(u_char* buf);

int get_hostlist(void);
#endif /* PROC_FILE_H */
