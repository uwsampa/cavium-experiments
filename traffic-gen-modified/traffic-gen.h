#ifndef __TRAFFIC_GEN_PKT_IO_H__
#define __TRAFFIC_GEN_PKT_IO_H__

#include <time.h> /* MODIFIED: added this include statement */

#define CYCLE_SHIFT	12
#define ETHERNET_CRC	4       /* Gigabit ethernet CRC in bytes */

#define MAC_ADDR_LEN	6
#define IP_ADDR_LEN	4

#define     IPD_MAX_PORTS   0xc41

/**
 * tx_task--a Framework for per-port per-packet TX tasks.
 *
 * - tx_task_t is the type of a tx_task, e.g., incrementing IP src
 *   address of the packet.
 * - tgpio_add_txf() and tgpio_del_txf() adds and removes a tx_task on a
 *   port.
 * - txf_dest_mac_inc(), txf_src_mac_inc() are two tx_tasks.
 * - tgpio_get_txf_ip() returns a tx_task for IP header field
 *   manipulation.
 */
#define MAX_TX_TASKS	16
typedef int (*tx_task_t)(int port);
extern int tgpio_add_txf(int port, tx_task_t ptask);
extern int tgpio_del_txf(int port, tx_task_t ptask);
extern int txf_dest_mac_inc(int port);
extern int txf_src_mac_inc(int port);
extern tx_task_t tgpio_get_txf_ip(int port, int is_src, int is_ipaddr);

typedef enum {
    PACKET_TYPE_IPV4_UDP,
    PACKET_TYPE_IPV6_UDP,
    PACKET_TYPE_IPV4_TCP,
    PACKET_TYPE_IPV6_TCP,
    PACKET_TYPE_802_3_PAUSE,
    PACKET_TYPE_CBFC_PAUSE,
    PACKET_TYPE_CJPAT,
    PACKET_TYPE_ETH_PKT, /* MODIFIED: added this packet type */
    PACKET_TYPE_HELP    /* best to keep this last */
} packet_type_t;

typedef enum {
    DATA_TYPE_ABC=0,
    DATA_TYPE_ZERO,
    DATA_TYPE_ONE,
    DATA_TYPE_INC,
    DATA_TYPE_DEC,
    DATA_TYPE_RAND,
    DATA_TYPE_HELP      /* best to keep this last */
} payload_t;

#define MAX_INSERT 8

typedef struct
{
    uint32_t                output_interface;       /* interface number */
    uint32_t                output_port;            /* Port number (not IPD) */
    uint64_t                output_percent_x1000;   /* percent*1000 */
    uint64_t                output_cycle_gap;
    uint64_t                output_packet_size;
    uint64_t                output_enable;
    uint64_t                output_count;
    packet_type_t           output_packet_type;
    payload_t               output_packet_payload;
    uint64_t                output_arp_reply_enable;
    uint64_t                src_mac;
    int32_t                 src_mac_inc;
    uint64_t                src_mac_min;
    uint64_t                src_mac_max;
    uint64_t                dest_mac;
    int32_t                 dest_mac_inc;
    uint64_t                dest_mac_min;
    uint64_t                dest_mac_max;
    uint64_t                vlan_size;
    uint8_t                 vlan[MAX_INSERT];
    uint32_t                src_ip;
    int32_t                 src_ip_inc;
    uint32_t                src_ip_min;
    uint32_t                src_ip_max;
    uint32_t                dest_ip;
    int32_t                 dest_ip_inc;
    uint32_t                dest_ip_min;
    uint32_t                dest_ip_max;
    uint32_t                ip_tos;
    uint16_t                src_port;
    int16_t                 src_port_inc;
    uint16_t                src_port_min;
    uint16_t                src_port_max;
    uint16_t                dest_port;
    int16_t                 dest_port_inc;
    uint16_t                dest_port_min;
    uint16_t                dest_port_max;
    int                     do_checksum;
    int                     bridge_port;
    int                     display_packet;
    int                     input_arp_reply_enable;
    int                     input_arp_request_enable;
    char *                  output_data;
    int                     promisc;  /* Promiscuous mode (default to 1) */
    int                     validate;
    int                     respect_backpressure;
    int                     higig; /* The number of HiGig bytes to include
    				    * before L2
				    */
    cvmx_higig_header_t     higig_header; /* The HiGig header included if
    					   * "higig" is set
					   */
    cvmx_ilk_la_nsp_compact_hdr_t ilk_la_header;
    cvmx_srio_tx_message_header_t srio;
    int                     ilk_la_mode; /* Interlaken LA mode */
    int                     port_valid;
    int                     count_crc;

    /*
     * Transmitter tasks
     */
    tx_task_t	tx_tasks[MAX_TX_TASKS];
    int		tx_ntasks;
    char        ipd_str[20];
} port_setup_t;

/**
 * port setup global
 */
extern CVMX_SHARED port_setup_t    port_setup[IPD_MAX_PORTS];

static inline int get_size_wire_overhead(int port)
{
    if (port_setup[port].ilk_la_mode)
        return 8 /*INTERFRAME_GAP*/ + sizeof(port_setup[port].ilk_la_header) + ETHERNET_CRC;
    else if (port_setup[port].higig)
        return 8 /*INTERFRAME_GAP*/ + port_setup[port].higig + ETHERNET_CRC;
    else if (port_setup[port].srio.u64)
        return 0;
    else
        return 12 /*INTERFRAME_GAP*/ + 8 /*MAC_PREAMBLE*/ + ETHERNET_CRC;
}

static inline int get_size_pre_l2(int port)
{
    if (port_setup[port].srio.u64)
    {
        /* TX needs to add SRIO header */
        return sizeof(port_setup[port].srio);
    }
    else if (port_setup[port].ilk_la_mode)
    {
        return sizeof(port_setup[port].ilk_la_header);
    }
    else
    {
        /*
	 * The preamble is created by hardware, so the length is zero
	 * for SW. In the higig case, the higig header replaces the
	 * preamble and we need to include it
	 */
        return port_setup[port].higig;
    }
}

static inline int get_size_l2(int port)
{

    /*
     * L2 header is two MAC addresses, optional VLAN stuff, and a L2
     * size/type
     */
    return MAC_ADDR_LEN*2 + port_setup[port].vlan_size + 2;
}

static inline int get_size_ip_header(int port)
{
    /*
     * We don't support options, so the size of the IP header is fixed for
     * IPv4 or IPv6
     */
    switch (port_setup[port].output_packet_type)
    {
        case PACKET_TYPE_IPV6_UDP:
        case PACKET_TYPE_IPV6_TCP:
            return 40;
        case PACKET_TYPE_802_3_PAUSE:
        case PACKET_TYPE_CBFC_PAUSE:
        case PACKET_TYPE_CJPAT:
            return 0;
        default:
            return 20;
    }
}

static inline int get_size_payload(int port)
{
    /*
     * The payload area is whatever is left after the previous headers. Note
     * that this does not include any UDP or TCP header
     */
    return port_setup[port].output_packet_size - get_size_ip_header(port) - get_size_l2(port);
}

static inline int get_end_pre_l2(int port)
{
    return get_size_pre_l2(port);
}

static inline int get_end_l2(int port)
{
    return get_end_pre_l2(port) + get_size_l2(port);
}

static inline int get_end_ip_header(int port)
{
    return get_end_l2(port) + get_size_ip_header(port);
}

static inline int get_end_payload(int port)
{
    return get_end_ip_header(port) + get_size_payload(port);
}


/**
 * Send packets out of one port.
 *
 * @port	The index for port_setup
 * @queue	The output PKO command queue
 * @pko_cmd	The PKO command word0
 * @hw_buffer	The pointer to the PKO buffer pointer
 * @output_cycle	output cycle counter
 * @pcount	packet counter
 *
 * @returns 1 for packet(s) sent and 0 otherwise.
 */
extern int tgpio_packet_transmitter(const int port, const uint64_t queue,
    cvmx_pko_command_word0_t *pko_cmd, cvmx_buf_ptr_t *hw_buffer,
    uint64_t *output_cycle, uint64_t *pcount);

/**
 * Calculates checksum for IP headers, always checksum on 4 octet
 * boundaries.
 */
extern unsigned short ip_fast_csum(char *iph, unsigned int ihl);

#endif
