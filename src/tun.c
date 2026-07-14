#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <linux/if_tun.h>

#include "tun.h"

static int tun_fd = -1;
static char *dev = NULL;

static int tun_alloc(char *dev){
    struct ifreq ifr;
    int fd, err;

    if((fd = open("/dev/net/tun",O_RDWR)) < 0){
        perror("Connot open TUN/TAP dev");
        exit(1);
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if(*dev){
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0){
        perror("Could not ioctl tun");
        close(fd);
        exit(1);
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

int tun_init(){
    if(tun_fd >= 0)
        return 0;
    if((dev = calloc(IFNAMSIZ, sizeof(char))) == NULL){
        perror("ERR: Could not calloc dev");
        return -1;
    }
    strncpy(dev, "tap0", IFNAMSIZ);
    tun_fd = tun_alloc(dev);

    printf("TAP device created: %s\n", dev);
    return 0;
}

int tun_read(void *buf, int len){
    return read(tun_fd, buf, len);
}

int tun_write(void *buf, int len){
    return write(tun_fd, buf, len);
}

int tun_free()
{
    if (tun_fd >= 0) {
        close(tun_fd);
        tun_fd = -1;
    }

    free(dev);
    dev = NULL;

    return 0;
}