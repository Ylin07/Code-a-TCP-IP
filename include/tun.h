#ifndef TUN_H
#define TUN_H

int tun_init();

int tun_read(void *buf, int len);
int tun_write(void *buf, int len);

int tun_free();

#endif