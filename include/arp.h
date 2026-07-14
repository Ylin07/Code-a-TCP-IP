#ifndef ARP_H
#define ARP_H

#include <stdint.h>
int arp_init();

int arp_handle(void *buf, int len);

int arp_request(uint32_t target_ip);

int arp_lookup(uint32_t ip, unsigned char *mac);

int arp_free();

#endif