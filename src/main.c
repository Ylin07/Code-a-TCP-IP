#include <stdio.h>

#include "arp.h"
#include "tun.h"

int main()
{
    unsigned char buf[2048];
    int len;

    if (tun_init() < 0) {
        fprintf(stderr, "Could not initialize TAP device\n");
        return -1;
    }

    if (arp_init() < 0) {
        fprintf(stderr, "Could not initialize ARP\n");
        tun_free();
        return -1;
    }

    printf("ARP program started\n");

    while (1) {
        len = tun_read(buf, sizeof(buf));

        if (len < 0) {
            perror("tun_read");
            break;
        }

        if (arp_handle(buf, len) < 0) {
            fprintf(stderr, "arp_handle failed\n");
            break;
        }
    }

    arp_free();
    tun_free();

    return 0;
}