#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>

int ipv4_handle(void *buf, int len);

int ipv4_send(
    const unsigned char *tmac,
    uint32_t tip,
    uint8_t protocol,
    const void *payload,
    int len
);

int ipv4_free();

#endif