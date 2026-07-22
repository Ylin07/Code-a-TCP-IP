#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "tun.h"
#include "arp.h"


// #define ETH_P_IP 0x0800    // IP报文
// #define ETH_P_ARP 0x0806   // ARP报文
#define ARP_ETHERNET 1     

#define ARP_REQUEST 1
#define ARP_REPLY   2

// 以太网帧头结构
// typedef struct{
//     unsigned char dst[ETH_ALEN];
//     unsigned char src[ETH_ALEN];
//     uint16_t type;  
// }__attribute__((packed)) eth_hdr;

// ARP报文结构
typedef struct{
    uint16_t hwtype;
    uint16_t protype;
    unsigned char hwsize;
    unsigned char prosize;
    uint16_t opcode;
    unsigned char smac[ETH_ALEN];
    uint32_t sip;
    unsigned char tmac[ETH_ALEN];
    uint32_t tip;
}__attribute__((packed)) arp_hdr;

// ARP数据包结构
typedef struct{
    eth_hdr eth;
    arp_hdr arp;
}__attribute__((packed)) arp_pkt;

static int arp_initial = 0;
static uint32_t local_ip;
static unsigned char local_mac[6] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02
};

#define ARP_CACHE_SIZE 16
typedef struct{
    int valid;
    uint32_t ip;
    unsigned char mac[ETH_ALEN];
} arp_entry;
static arp_entry arp_cache[ARP_CACHE_SIZE];

int arp_init(){
    if(arp_initial) return 0;
    if(inet_pton(AF_INET, "10.0.0.2", &local_ip) != 1){
        fprintf(stderr,"ERR: Could not initialize ARP IP\n");
        return -1;
    }
    memset(arp_cache, 0, sizeof(arp_cache));
    arp_initial = 1;
    return 0;
}

static int arp_reply(const arp_pkt *packet){
    arp_pkt reply;

    memset(&reply, 0, sizeof(reply));
    // 以太网帧头部
    memcpy(reply.eth.dst, packet->eth.src,ETH_ALEN);
    memcpy(reply.eth.src, local_mac,ETH_ALEN);
    reply.eth.type = htons(ETH_P_ARP);
    // ARP头部
    reply.arp.hwtype = htons(ARP_ETHERNET);
    reply.arp.protype = htons(ETH_P_IP);
    reply.arp.hwsize = ETH_ALEN;
    reply.arp.prosize = 4;
    reply.arp.opcode = htons(ARP_REPLY);
    
    memcpy(reply.arp.smac, local_mac, ETH_ALEN);
    reply.arp.sip = local_ip;
    memcpy(reply.arp.tmac, packet->arp.smac, ETH_ALEN);
    reply.arp.tip = packet->arp.sip;

    if(tun_write(&reply, sizeof(reply)) < 0){
        perror("ERR: Could not write ARP reply");
        return -1;
    }
    return 0;
}

static int arp_cache_find(uint32_t ip){
    int i;
    for(i=0; i<ARP_CACHE_SIZE; i++){
        if(arp_cache[i].valid && (arp_cache[i].ip == ip))
            return i;
    }
    return -1;
}

static int arp_cache_update(uint32_t ip, const unsigned char *mac){
    int i;
    int index;
    index = arp_cache_find(ip);
    if(index >= 0){
        memcpy(arp_cache[index].mac, mac, ETH_ALEN);
        return 0;
    }
    for(i=0; i<ARP_CACHE_SIZE; i++){
        if(!arp_cache[i].valid){
            arp_cache[i].valid = 1;
            arp_cache[i].ip = ip;
            memcpy(arp_cache[i].mac, mac, ETH_ALEN);
            return 0;
        }
    }
    arp_cache[0].valid = 1;
    arp_cache[0].ip = ip;
    memcpy(arp_cache[0].mac, mac, ETH_ALEN); 
    return 0;
}

int arp_lookup(uint32_t ip, unsigned char *mac){
    int index;
    if(mac == NULL) return -1;
    index = arp_cache_find(ip);
    if(index < 0) return -1;
    memcpy(mac, arp_cache[index].mac, ETH_ALEN);
    return 0;
}

int arp_request(uint32_t target_ip){
    arp_pkt request;

    memset(&request, 0, sizeof(request));
    // 以太网头部
    // 目标地址所有位全为1时 广播发送请求
    memset(request.eth.dst, 0xff, ETH_ALEN);
    memcpy(request.eth.src, local_mac, ETH_ALEN);
    request.eth.type = htons(ETH_P_ARP);
    // ARP头部
    request.arp.hwtype = htons(ARP_ETHERNET);
    request.arp.protype = htons(ETH_P_IP);
    request.arp.hwsize = ETH_ALEN;
    request.arp.prosize = 4;
    request.arp.opcode = htons(ARP_REQUEST);

    memcpy(request.arp.smac, local_mac, ETH_ALEN);
    request.arp.sip = local_ip;
    // 由于request清零 所以mac默认是00:00:00:00:00:00 不用赋值
    request.arp.tip = target_ip;

    if(tun_write(&request, sizeof(request)) < 0){
        perror("ERR: Could not write ARP request");
        return -1;
    }
    return 0;
}

int arp_handle(void *buf, int len){
    arp_pkt *packet;
    uint16_t opcode;
    
    if(!arp_initial || buf==NULL) return -1;
    if(len < (int)sizeof(arp_pkt)) return 0;
    packet = buf;
    // 不是ARP包
    if(ntohs(packet->eth.type) != ETH_P_ARP) return 0;
    // 不是以太网 + IPv4 ARP
    if(ntohs(packet->arp.hwtype) != ARP_ETHERNET) return 0;
    if(ntohs(packet->arp.protype) != ETH_P_IP) return 0;
    // hwsize 和 prosize 要符合要求
    if(packet->arp.hwsize != ETH_ALEN) return 0;
    if(packet->arp.prosize != 4) return 0;

    opcode = ntohs(packet->arp.opcode);
    if(opcode == ARP_REQUEST){
        // 如果REQUEST请求不是本机的IP 则忽略
        arp_cache_update(packet->arp.sip, packet->arp.smac);
        if(packet->arp.tip != local_ip) return 0;
        return arp_reply(packet);
    }else if(opcode == ARP_REPLY){
        // 从packet中学习发送IP和发送mac的映射关系
        arp_cache_update(packet->arp.sip, packet->arp.smac);
        return 0;
    }
    return 0;
}

int arp_free(){
    memset(arp_cache, 0, sizeof(arp_cache));
    arp_initial = 0;
    local_ip = 0;
    return 0;
}
