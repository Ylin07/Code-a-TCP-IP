#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <linux/if_ether.h>

// 以太网帧头结构
typedef struct{
    unsigned char dst[ETH_ALEN];
    unsigned char src[ETH_ALEN];
    uint16_t type;  
}__attribute__((packed)) eth_hdr;

int arp_init();

int arp_handle(void *buf, int len);

int arp_request(uint32_t target_ip);

int arp_lookup(uint32_t ip, unsigned char *mac);

int arp_free();

#endif