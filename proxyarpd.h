#ifndef __PROXYARPD_H_
#define __PROXYARPD_H_

#include <sys/types.h>
#include <stdint.h>
#include <pthread.h>

#define PROXYARPD_VERSION	"1.0.0"
#define MAX_PACKET_LEN		1800

struct ether_arphdr {
    uint8_t 		dst_mac[6], src_mac[6];
    uint16_t		pkt_type;
    uint16_t		hw_type, pro_type;
    uint8_t		hw_len, pro_len;
    uint16_t		arp_op;
    uint8_t		sender_eth[6], sender_ip[4];
    uint8_t		target_eth[6], target_ip[4];
};

extern int		verbose_flag;

#endif
