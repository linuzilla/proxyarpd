#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "proxyarpd.h"
#include "utils.h"
#include "packet.h"

#define ETHWTYPE        1
#define ARPREQUEST        1
#define ARPREPLY        2

static char		*program_name	  = NULL;
int			verbose_flag = 0;
int			debug_flag   = 0;

static int         number_of_ips = 0;
static in_addr_t *ip_pool = NULL;


static uint8_t network_packet[MAX_PACKET_LEN];
static struct ether_arphdr *pkt = (struct ether_arphdr *) &network_packet;
static short eth_p_arp;
struct in_addr *src_ip;
struct in_addr *tar_ip;

static unsigned char local_mac[6] = { 0, 8, 0, 0xab, 0xcd, 0xef };

static union proxy_arp_mac_address_t {
    uint64_t value;
    char mac[6];
} proxy_mac;


static char* toLower (char* s) {
    for (char *p = s; *p; p++)
        *p = tolower (*p);
    return s;
}

static pcre2_code * compile_regex (const char *pattern) {
    int errornumber = 0;
    PCRE2_SIZE erroroffset;

    pcre2_code *re = pcre2_compile (
                         (PCRE2_SPTR) pattern,  /* the pattern */
                         PCRE2_ZERO_TERMINATED, /* indicates pattern is zero-terminated */
                         0,                     /* default options */
                         &errornumber,          /* for error number */
                         &erroroffset,          /* for error offset */
                         NULL);                 /* use default compile context */

    if (re == NULL) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message (errornumber, buffer, sizeof (buffer));
        printf ("PCRE2 compilation failed at offset %d: %s\n", (int)erroroffset,
                buffer);
        exit (-1);
    }
    return re;
}

static uint64_t parsing_mac (const char *mac) {
    pcre2_code *re;
    pcre2_match_data *match_data;
    int length = (int) strlen (mac);

    if (strchr (mac, ':') != NULL) {
        re = compile_regex ("^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$");
    } else if (strchr (mac, '.') != NULL) {
        re = compile_regex ("^[0-9a-f]{4}\\.[0-9a-f]{4}\\.[0-9a-f]{4}$");
    } else {
        re = compile_regex ("^[0-9a-f]{12}$");
    }

    match_data = pcre2_match_data_create_from_pattern (re, NULL);

    int rc = pcre2_match (
                 re,                   /* the compiled pattern */
                 (PCRE2_SPTR) mac,              /* the subject string */
                 length,       /* the length of the subject */
                 0,                    /* start at offset 0 in the subject */
                 0,                    /* default options */
                 match_data,           /* block for storing the result */
                 NULL);                /* use default match context */

    pcre2_match_data_free (match_data);  /* Release memory used for the match */
    pcre2_code_free (re);                /*   data and the compiled pattern. */

    if (rc < 0)    {
        switch (rc)        {
        case PCRE2_ERROR_NOMATCH:
            printf ("No match\n");
            break;
        /*
        Handle other special cases if you like
        */
        default:
            printf ("Matching error %d\n", rc);
            break;
        }
        exit (-1);
    }

    uint64_t value = 0L;
    int bv = 0;
    int counter = 0;

    for (int i = length - 1; i >= 0; i--) {
        if (mac[i] >= '0' && mac[i] <= '9') {
            bv >>= 4;
            bv += (mac[i] - '0') << 4;
            counter++;
        } else if (mac[i] >= 'a' && mac[i] <= 'f') {
            bv >>= 4;
            bv += (mac[i] - 'a' + 10) << 4;
            counter++;
        } else {
            continue;
        }
        if (counter % 2 == 0) {
            value <<= 8;
            value += bv;
            counter = 0;
            bv = 0;
        }
//        printf ("%d: %" PRIu64 "\n", i, value);
    }
    return value;
}

static void parsing_ips (char **argv, int from, int num) {
    pcre2_code *re = compile_regex ("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    pcre2_match_data *match_data;

    ip_pool = malloc (num  * sizeof (in_addr_t));

    for (int i = 0; i < num; i++) {
        char *ipaddr = argv[from + i];
        struct in_addr inp;

        match_data = pcre2_match_data_create_from_pattern (re, NULL);

        int rc = pcre2_match (
                     re,                   /* the compiled pattern */
                     (PCRE2_SPTR) ipaddr,              /* the subject string */
                     strlen (ipaddr),      /* the length of the subject */
                     0,                    /* start at offset 0 in the subject */
                     0,                    /* default options */
                     match_data,           /* block for storing the result */
                     NULL);                /* use default match context */

        pcre2_match_data_free (match_data);  /* Release memory used for the match */

        if (rc < 0)    {
            switch (rc)        {
            case PCRE2_ERROR_NOMATCH:
                printf ("No match\n");
                break;
            /*
            Handle other special cases if you like
            */
            default:
                printf ("Matching error %d\n", rc);
                break;
            }
            exit (-1);
        }

        if (inet_aton (ipaddr, &inp) == 0) {
            fprintf (stderr, "%s: invalid IP format\n", ipaddr);
            exit (-1);
        }

        ip_pool[i] = inp.s_addr;
    }

    pcre2_code_free (re);                /*   data and the compiled pattern. */
}

static void print_arprequest (void) {
    fprintf (stderr, "arp who-has %s tell %s (%s)\n",
             print_ip (pkt->target_ip),
             print_ip (pkt->sender_ip),
             print_ether (pkt->sender_eth));
}

static void print_arpreply (const int  showmac) {
    if (showmac)
        fprintf (stderr, "%s %s ",
                 print_ether (pkt->dst_mac),
                 print_ether (pkt->src_mac));

    fprintf (stderr, "arp reply %s is-at %s (tell %s %s)\n",
             print_ip    (pkt->sender_ip),
             print_ether (pkt->sender_eth),
             print_ip    (pkt->target_ip),
             print_ether (pkt->target_eth));
}

static void send_arp_reply (int fd, ssize_t len, struct msghdr * msg) {
    uint8_t buffer[4];

    pkt->arp_op = htons (ARPREPLY);

    memcpy (& (pkt->dst_mac), & (pkt->src_mac), 6);
    memcpy (& (pkt->src_mac), local_mac, 6);

    memcpy (& (pkt->target_eth), & (pkt->sender_eth), 6);
    memcpy (& (pkt->sender_eth), proxy_mac.mac,  6);

    memcpy (buffer, pkt->sender_ip, 4);
    memcpy (pkt->sender_ip, pkt->target_ip, 4);
    memcpy (pkt->target_ip, pkt->sender_ip, 4);

    print_arpreply (1);

    if (sendto (fd, network_packet, len, 0, msg->msg_name, msg->msg_namelen) < 0) {
        perror ("sendto");
    }
}

static void arp_analyzer (int vlanid, ssize_t len, int fd, struct msghdr * msg) {
    if (pkt->pkt_type != eth_p_arp) {
        if (verbose_flag > 5) {
            printf ("type: ( %x != %x), vlan: %d, packet size: %lu\n", pkt->pkt_type, eth_p_arp, vlanid, len);
        }
        return;
    }

    if (verbose_flag > 3) {
        printf ("vlan: %d, packet size: %lu\n", vlanid, len);
    }

    switch (ntohs (pkt->arp_op)) {
    case ARPREQUEST:
        print_arprequest();

        for (int i = 0; i < number_of_ips; i++) {
            if (ip_pool[i] == tar_ip->s_addr) {
                send_arp_reply (fd, len, msg);
                break;
            }
        }
        break;

    case ARPREPLY:
        print_arpreply (1);
        break;
    }
}

int main (int argc, char *argv[]) {
    char		*cp;
    int		help_flag    = 0;
    int		c;
    int		option_index = 0;
    char *listen_interface = "eth0";

    struct option	long_options[] = {
        { "verbose"		, 0, 0, 'v' },
        { "debug"		, 0, 0, 'd' },
        { "help"		, 0, 0, 'h' },
        { "interface"		, 1, 0, 'i' },
        { 0			, 0, 0,  0  }
    };



    program_name = ((cp = strrchr (argv[0], '/')) != NULL) ? cp + 1 : argv[0];

    fprintf (stderr, "\r\n"
             "%s v%s, Copyright (c) 2023 written by Mac Liu [ linuzilla@gmail.com ]\r\n\n",
             program_name, PROXYARPD_VERSION);

    fprintf (stderr, "Check machine\'s byte order: ");

    if (check_byte_ending () == -1) {
        fprintf (stderr, " ... good\r\n");
    } else {
        fprintf (stderr, " ... error\r\n");
        exit (0);
    }

    while ((c = getopt_long (argc, argv, "vdhi:",
                             long_options, &option_index)) != EOF) {
        switch (c) {
        case 'v':
            verbose_flag++;
            break;
        case 'd':
            debug_flag = 1;
            break;
        case 'h':
            help_flag = 1;
            break;
        case 'i':
            listen_interface = optarg;
            break;
        case 0:
            exit (0);
            break;
        default:
        case '?':
            exit (0);
            break;
        }
    }

    if (argc - optind < 2 || help_flag) {
        printf ("%s [-options] mac-address ip ...\n"
                "\t-i (--interface) interface\n"
                "\t-v (--verbose)\n"
                "\t-d (--debug)\n"
                "\t-h (--help)\n",
                program_name);
        exit (0);
    }

    proxy_mac.value = parsing_mac (toLower (argv[optind]));

    number_of_ips = argc - optind - 1;

    parsing_ips (argv, optind + 1, number_of_ips);

    struct linux_packet_t *linuxPacket = new_linux_packet (listen_interface);

    if (linuxPacket != NULL) {
        eth_p_arp = ntohs (ETH_P_ARP);
        src_ip = (struct in_addr *) pkt->sender_ip;
        tar_ip = (struct in_addr *) pkt->target_ip;

        while (true) {
            linuxPacket->receive ((char *) network_packet, sizeof (network_packet), arp_analyzer);
        }
    }

    return 0;
}
