#ifndef ARP_H
#define ARP_H

int arp_init();

int arp_handle(void *buf, int len);

int arp_free();

#endif