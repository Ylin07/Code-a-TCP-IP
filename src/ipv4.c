#include "ipv4.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "arp.h"
#include "tun.h"

#define IPV4_VERSION 4
#define IPV4_IHL     5
#define IPV4_TTL     64

#define IPV4_HEADER_SIZE 20
#define IPV4_FRAME_SIZE  2048

typedef struct  {
    uint8_t version : 4;
    uint8_t ihl : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags : 3;
    uint16_t frag : 13;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t sip;
    uint32_t tip;
} __attribute__((packed)) ipv4_hdr;

typedef struct {
    eth_hdr eth;
    ipv4_hdr ip;
    unsigned char data[];    
} __attribute__((packed)) ipv4_pkt;

static int ipv4_initial = 0;
// IP包ID计数器
static uint16_t ipv4_id = 0;
static uint32_t local_ip;
static unsigned char local_mac[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

uint16_t checksum(void *addr, int count)
{
    register uint32_t sum = 0;
    uint16_t * ptr = addr;
    while( count > 1 )  {
        sum += * ptr++;
        count -= 2;
    }
    if( count > 0 )
        sum += * (uint8_t *) ptr;
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

int ipv4_init(){
    if(ipv4_initial) return 0;
    if(inet_pton(AF_INET, "10.0.0.2", &local_ip) != 1){
        fprintf(stderr, "ERR: Could not initialize IPv4 address\n");
        return -1;
    }
    ipv4_id = 0;
    ipv4_initial = 1;
    return 0;
}

int ipv4_send(
    const unsigned char *tmac,
    uint32_t tip,
    uint8_t protocol,
    const void *payload,
    int len
){
    unsigned char frame[IPV4_FRAME_SIZE];
    ipv4_pkt *packet;
    int frame_len;
    if(tmac == NULL || payload == NULL) return -1;
    if(len < 0) return -1;

    frame_len = sizeof(eth_hdr) + sizeof(ipv4_hdr) + len;
    if(frame_len > IPV4_FRAME_SIZE) return -1;
    // 初始化packet
    memset(frame, 0, sizeof(frame));
    packet = (ipv4_pkt *)frame;

    // eth头初始化
    memcpy(packet->eth.dst, tmac, ETH_ALEN);
    memcpy(packet->eth.src, local_mac, ETH_ALEN);
    packet->eth.type = htons(ETH_P_IP);
    // IP头初始化
    packet->ip.version = IPV4_VERSION;
    packet->ip.ihl = IPV4_IHL;
    packet->ip.tos = 0;
    packet->ip.len = htons(sizeof(ipv4_hdr) + len);
    packet->ip.id = htons(ipv4_id++);
    packet->ip.frag = 0;
    packet->ip.ttl = IPV4_TTL;
    packet->ip.proto = protocol;
    packet->ip.csum = 0;
    packet->ip.sip = local_ip;
    packet->ip.tip = tip;
    memcpy(packet->data, payload, len);
    // checksum计算
    packet->ip.csum = checksum(&packet->ip, sizeof(ipv4_hdr));

    if(tun_write(frame, frame_len) < 0){
        perror("ERR: Could not write IPv4 packet");
        return -1;
    }
    return 0;
}

int ipv4_handle(void *buf, int len){
    eth_hdr *eth;
    ipv4_hdr *ip;
    unsigned char *payload;

    int header_len;
    int total_len;
    int payload_len;

    uint16_t fragment;

    if(buf == NULL) return -1;
    // 至少要满足最小长度
    if(len < (int)(sizeof(eth_hdr) + sizeof(ipv4_hdr))) return 0;

    eth = buf;
    if(ntohs(eth->type) != ETH_P_IP) return 0;
    ip = (ipv4_hdr *)((unsigned char *)buf + sizeof(eth_hdr));
    // 处理ip头部字段
    if(ip->version != IPV4_VERSION) return 0;
    header_len = (ip->ihl & 0xf) * 4;
    if(header_len < IPV4_HEADER_SIZE) return 0;
    if(len < (int)sizeof(eth_hdr) + header_len) return 0;
    total_len = ntohs(ip->len);
    if((total_len < header_len) || (total_len > len-(int)sizeof(eth_hdr))) return 0;
    // 只接受发给当前用户态协议栈的报文
    if(ip->tip != local_ip) return 0;
    // 校验校验和
    if(checksum(ip, header_len) != 0) return 0;
    // 处理分片
    fragment = ntohs(ip->frag);
    if((fragment & 0x3fff) != 0) return 0;

    payload = (unsigned char *)ip + header_len;
    payload_len = total_len - header_len;

    // 根据IPv4的ICMP字段分发
    if(ip->proto == IPPROTO_ICMP){
        // 这里暂时保留
        return 0;
    }
    return 0;
}

int ipv4_free(){
    ipv4_initial = 0;
    ipv4_id = 0;
    local_ip = 0;
    return 0;
}