#include <linux/inet.h> /*in_aton()*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>/*NF_IP_PRE_FIRST*/
#include <linux/skbuff.h>
#include <linux/socket.h>/*PF_INET*/
#include <linux/string.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "file.h"
#include "hash.h"

#define ETHALEN    14
#define SNF_NUMBER 1

#define NIPQUAD(x)                                                             \
    ((u_char*)&x)[0], ((u_char*)&x)[1], ((u_char*)&x)[2], ((u_char*)&x)[3]

#if !defined(__linux__)
static inline u_int set_bit(int n, int p) { return n | (1 << p); }
#endif
static inline u_int get_bit(u_int p, volatile u_long n) { return (n >> p) & 1; }

static bool hit_http(const u_char* data);
static bool hit_host(const u_char* host);
static int  get_http_host(const u_char* data, u_char* host, int len);

static struct nf_hook_ops g_nfho;

static bool hit_http(const u_char* data) {
    const u_char*   p;
    int             len;
    char            ch;
    volatile u_long state;

    p = (const u_char*)strstr((const char*)data, "\r\n");
    if (!p) {
        return 0;
    }

    len = p - data;
    for (p = data, state = 0; p != data + len && state != 0xf; ++p) {
        ch = *p;

        switch (ch) {
            case 'H':
                set_bit(0, &state);
                break;
            case 'T':
                if (get_bit(0, state)) {
                    if (get_bit(1, state)) {
                        set_bit(2, &state);
                    } else {
                        set_bit(1, &state);
                    }
                } else {
                    state = 0;
                }
                break;
            case 'P':
                if (get_bit(0, state) && get_bit(1, state) &&
                    get_bit(2, state)) {
                    set_bit(3, &state);
                } else {
                    state = 0;
                }

                break;
            default:
                state = 0;
                break;
        }
    }

    return state == 0xf;
}

static bool hit_host(const u_char* host) {
    /* return find_from_htable(g_htable, host) ? 1 : 0; */
    return host_hash_find(host, strlen(host)) ? true : false;
}

static int get_http_host(const u_char* data, u_char* host, int len) {
    u_char* host_head = NULL;
    u_char* host_val  = NULL;
    u_char* host_tail = NULL;
    int     host_len  = 0;

    /* Locate Host */
    host_head = strstr(data, "Host: ");
    if (!host_head) {
        return -1;
    }

    host_val = host_head + 6;

    /* 1. Get \r\n */
    host_tail = strstr(host_val, "\r\n");
    if (host_tail) {
        host_len = host_tail - host_val;
    } else {
        host_len = strlen(host_val);
    }

    /* Get Host */
    snprintf(host, host_len + 1, "%s", host_val);
    str_trailing(host);

    return strlen(host);
}

u_int snf_hook(const struct nf_hook_ops* ops,
               struct sk_buff*           skb,
               const struct net_device*  in,
               const struct net_device*  out,
#ifndef __GENKSYMS__
               const struct nf_hook_state* state
#else
               int (*okfn)(struct sk_buff*)
#endif
) {
    struct iphdr*  iph;
    struct tcphdr* tcph;
    struct arphdr* arph;
    int            tot_len;
    u_char*        data;
    u_char         host[MAX_HOST_STRLEN];

    if (skb == NULL) return NF_ACCEPT;

    iph = ip_hdr(skb);



    if (iph && iph->protocol && iph->protocol == IPPROTO_TCP) {
        tot_len = ntohs(iph->tot_len);

        if (skb) {
            tcph = tcp_hdr(skb);

            /* Get payload */
            data = (u_char*)((u_char*)tcph + (tcph->doff << 2));

            /* Get HTTP */
            if (!hit_http(data)) {
                /* ACCEPT if not HTTP */
                return NF_ACCEPT;
            }

            memset(host, 0, sizeof(host));
            if (get_http_host(data, host, sizeof(host)) < 0) {
                /* ACCEPT if no Host got */
                return NF_ACCEPT;
            }

            if (hit_host(host) == true) {
                /* Hit Host */
                printk(KERN_INFO "saddr: %d.%d.%d.%d daddr: %d.%d.%d.%d\n",
                       NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));

                /* Drop if matched */
                printk(KERN_INFO "Dropped: Host (%s) hit black-list\n", host);
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

static int __init filter_init(void) {
    int ret;

    printk(KERN_INFO "Start Simple Netfilter\n");

    if (get_hostlist() <= 0) {
        return 0;
    }

    g_nfho.hook     = snf_hook;
    g_nfho.pf       = PF_INET;
    g_nfho.priority = NF_IP_PRI_FIRST;
    g_nfho.hooknum  = NF_INET_LOCAL_IN;

    ret = nf_register_hook(&g_nfho);
    if (ret < 0) {
        printk(KERN_INFO "%s\n", "can't modify skb hook!");
        return ret;
    }

    return 0;
}

static void filter_done(void) {
    printk(KERN_INFO "Filter done \n");

    host_hash_destroy();

    nf_unregister_hook(&g_nfho);
}

module_init(filter_init);
module_exit(filter_done);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("whiothes");
MODULE_DESCRIPTION("A Simple NetFilter Module");
