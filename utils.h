#ifndef _LIUJC_UTILS_H_
#define _LIUJC_UTILS_H_

#include <stdint.h>

uint8_t * text2macaddr (const char *str, uint8_t *macaddr);
uint8_t * print_ether  (const uint8_t *mac);
uint8_t * print_mac    (const uint8_t *mac);
uint8_t * print_ip     (const uint8_t *ipstr);
uint8_t * timet_2_mysql_datetime (const time_t *ptr);
int	 check_byte_ending (void);


#endif
