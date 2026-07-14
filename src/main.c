#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdio.h>

#include "arp.h"
#include "tun.h"

static void print_mac(const unsigned char *mac)
{
    printf(
        "%02x:%02x:%02x:%02x:%02x:%02x]\n",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
}

int main()
{
    unsigned char buf[2048];
    unsigned char mac[ETH_ALEN];

    struct in_addr target_ip;

    int len;

    /*
     * 创建 tap0。
     */
    if (tun_init() < 0) {
        fprintf(stderr, "ERR: Could not initialize TAP\n");
        return -1;
    }

    /*
     * 初始化用户态 ARP：
     *
     * IP  = 10.0.0.2
     * MAC = 02:00:00:00:00:02
     */
    if (arp_init() < 0) {
        fprintf(stderr, "ERR: Could not initialize ARP\n");
        tun_free();
        return -1;
    }

    /*
     * 查询 Linux tap0 的 IP。
     */
    if (inet_pton(AF_INET, "10.0.0.1", &target_ip) != 1) {
        fprintf(stderr, "ERR: Invalid target IP\n");

        arp_free();
        tun_free();

        return -1;
    }
    printf("Configure tap0, then press Enter...\n");
    getchar();
    
    printf("ARPING 10.0.0.1\n");

    /*
     * 发送：
     *
     * Who has 10.0.0.1?
     * Tell 10.0.0.2
     */
    if (arp_request(target_ip.s_addr) < 0) {
        fprintf(stderr, "ERR: Could not send ARP request\n");

        arp_free();
        tun_free();

        return -1;
    }

    /*
     * 等待 Linux 返回 ARP Reply。
     */
    while (1) {
        len = tun_read(buf, sizeof(buf));

        if (len < 0) {
            perror("ERR: Could not read TAP");
            break;
        }

        /*
         * 如果收到的是 ARP Reply，
         * arp_handle() 会更新 ARP 缓存。
         */
        if (arp_handle(buf, len) < 0) {
            fprintf(stderr, "ERR: Could not handle ARP packet\n");
            break;
        }

        /*
         * 每处理完一个数据包，都检查目标地址
         * 是否已经进入 ARP 缓存。
         */
        if (arp_lookup(target_ip.s_addr, mac) == 0) {
            printf("Reply from 10.0.0.1 [");
            print_mac(mac);

            break;
        }
    }

    arp_free();
    tun_free();

    return 0;
}