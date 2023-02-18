#include <stdio.h>
#include <string.h>
#include <sys/types.h>

typedef enum { true = 1, false = 0 } bool;

static u_int set_bit(int n, int p) { return n | (1 << p); }
static u_int get_bit(int n, int p) { return (n >> p) & 1; }

static bool hit_http(const u_char* data) {
    const u_char* p;
    int           len;
    char          ch;
    u_int         state;

    p = (const u_char*)strstr((const char*)data, "\r\n");
    if (!p) {
        return 0;
    }
    len = p - data;

    for (p = data, state = 0; p != data + len && state != 0xf; ++p) {
        ch = *p;

        switch (ch) {
            case 'H':
                set_bit(&state, 0);
                break;
            case 'T':
                if (get_bit(state, 0)) {
                    if (get_bit(state, 1)) {
                        set_bit(&state, 2);
                    } else {
                        set_bit(&state, 1);
                    }
                } else {
                    state = 0;
                }
                break;
            case 'P':
                if (get_bit(state, 0) == 1 && get_bit(state, 1) == 1 &&
                    get_bit(state, 2) == 1) {
                    set_bit(&state, 3);
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

int main(void) {
    u_char buf[] = "GET / HTTP/1.1\r\n";
    printf("%d\n", hit_http(buf));

    strcpy(buf, "GET / HTT");
    printf("%d\n", hit_http(buf));
}
