#include <stdio.h>

#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-pko.h"
#include "cvmx-higig.h"
#include "cvmx-srio.h"
#include "cvmx-ilk.h"

#include "traffic-gen.h"

unsigned short ip_fast_csum(char *iph, unsigned int ihl) __attribute__ ((__noinline__));
unsigned short ip_fast_csum(char *iph, unsigned int ihl)
{

    unsigned int csum = 0;
    register char *arg1 asm ("$4") = iph;
    register unsigned int arg2 asm ("$5") = ihl;

    asm volatile (
        "    .set push                 # ip_fast_csum\n"
        "    cins   $5,$5,2,0x1f       # end pointer offset    \n"
        "    lw     $2,0($4)           # load first word       \n"
        "    lw     $6,4($4)           # load 2nd word         \n"
        "    lw     $3,8($4)           # load 3rd word         \n"
        "    daddu  $8,$4,$5           # end pointer           \n"
        "    lw     $5,12($4)          # load 4th word         \n"
        "    addu   $2,$6,$2           # csum = fist + 2nd     \n"
        "    sltu   $6,$2,$6           # check for carry       \n"
        "    addu   $2,$2,$3           # csum += 3rd           \n"
        "    addu   $2,$2,$6           # csum += carry         \n"
        "    sltu   $3,$2,$3           # check for carry       \n"
        "    addu   $2,$2,$5           # csum += 4th           \n"
        "    addu   $2,$2,$3           # csum += carry         \n"
        "    sltu   $5,$2,$5           # check for carry       \n"
        "    addu   $3,$5,$2           # csum += carry         \n"
        "    daddiu $7,$4,16           # offset to next        \n"
        "2:  lw     $2,0($7)           # load next word        \n"
        "    daddiu $7,$7,4            # offset of next word   \n"
        "    addu   $3,$3,$2           # csum += next_word     \n"
        "    sltu   $2,$3,$2           # check for carry       \n"
        "    bne    $7,$8,2b           # check for end ptr     \n"
        "    addu   $3,$2,$3           # csum += carry         \n"
        "                              # Now fold the csum     \n"
        "    move   $2,$3                                      \n"
        "    sll    $3,$2,0x10                                 \n"
        "    addu   $2,$2,$3                                   \n"
        "    sltu   $3,$2,$3                                   \n"
        "    srl    $2,$2,0x10                                 \n"
        "    addu   $2,$2,$3                                   \n"
        "    xori   $2,$2,0xffff                               \n"
        "    andi   $2,$2,0xffff                               \n"
        "    move   %0,$2                                      \n"
        "    jr     $31                                        \n"
        "    nop                                               \n"
       : "=r" (csum)
       : "r" (arg1), "r" (arg2), "0" (csum)
       : "$2", "$3", "$6", "$7", "$8", "memory");

    return csum;
}

/**
 * Convert a pointer to a MAC address into a 64bit number
 * containing the MAC address. Handle unaligned cases.
 *
 * @param mac    MAC address to read
 *
 * @return MAC address as a 64bit number
 */
static inline uint64_t mac_to_uint64(char *mac)
{
    uint64_t m;
    CVMX_LOADUNA_INT64(m, mac, 0);
    return m>>16;
}


/**
 * Store a 64bit number into a MAC address pointer. Handler the
 * unaligned case.
 *
 * @param m      Mac address
 * @param mac    Place to store it
 */
static inline void uint64_to_mac(uint64_t m, char *mac)
{
    CVMX_STOREUNA_INT32(m>>16, mac, 0);
    CVMX_STOREUNA_INT16(m&0xffff, mac, 4);
}

int tgpio_add_txf(int port, tx_task_t ptask)
{
    int i;
    port_setup_t *port_tx;

    if (!ptask)
        return 0;

    port_tx = port_setup + port;

    for (i = 0; i < port_tx->tx_ntasks; i++)
        if (port_tx->tx_tasks[i] == ptask)
	    return 0; /* it's already there */

    if (i < MAX_TX_TASKS)
    {
        port_tx->tx_tasks[i] = ptask;
	port_tx->tx_ntasks = i + 1;
	return 0;
    }

    return 1; /* tx table full */
}

int tgpio_del_txf(int port, tx_task_t ptask)
{
    int i, j;
    port_setup_t *port_tx;

    if (!ptask)
        return 0;

    port_tx = port_setup + port;
    for (i = 0; i < port_tx->tx_ntasks; i++)
        if (port_tx->tx_tasks[i] == ptask)
	    break;

    if (i == port_tx->tx_ntasks)
        return 0;

    for (j = i + 1; j < port_tx->tx_ntasks; j++)
    {
        port_tx->tx_tasks[i] = port_tx->tx_tasks[j];
	i++;
    }

    port_tx->tx_ntasks--;

    return 0;
}

static int txf_src_port_inc(int port)
{
    int begin_ip;
    char *data;
    port_setup_t *port_tx;

    port_tx = port_setup + port;
    data = port_tx->output_data;

    begin_ip = get_end_l2(port);
    if (cvmx_unlikely(port_setup[port].src_port_inc))
    {
        int p = *(uint16_t*)(data + begin_ip + 20);
        p += port_setup[port].src_port_inc;
        if (p < port_setup[port].src_port_min)
            p = port_setup[port].src_port_max;
        else if (p > port_setup[port].src_port_max)
            p = port_setup[port].src_port_min;
        *(uint16_t*)(data + begin_ip + 20) = p;
    }

    return 0;
}

static int txf_dest_port_inc(int port)
{
    int begin_ip = get_end_l2(port);
    char *data;
    port_setup_t *port_tx;

    port_tx = port_setup + port;
    data = port_tx->output_data;

    if (cvmx_unlikely(port_setup[port].dest_port_inc))
    {
        int p = *(uint16_t*)(data + begin_ip + 22);
        p += port_setup[port].dest_port_inc;
        if (p < port_setup[port].dest_port_min)
            p = port_setup[port].dest_port_max;
        else if (p > port_setup[port].dest_port_max)
            p = port_setup[port].dest_port_min;
        *(uint16_t*)(data + begin_ip + 22) = p;
    }

    return 0;
}

static int txf_src_ip_inc(int port)
{
    int begin_ip = get_end_l2(port);
    char *data;
    port_setup_t *port_tx;

    port_tx = port_setup + port;
    data = port_tx->output_data;

    if (cvmx_unlikely(port_setup[port].src_ip_inc))
    {
        int64_t p = *(uint32_t*)(data + begin_ip + 12);
        p += port_setup[port].src_ip_inc;
        if (p < port_setup[port].src_ip_min)
            p = port_setup[port].src_ip_max;
        else if (p > port_setup[port].src_ip_max)
            p = port_setup[port].src_ip_min;
        *(uint32_t*)(data + begin_ip + 12) = p;

        /* IP checksum */
        data[begin_ip + 10] = 0;
        data[begin_ip + 11] = 0;
        *(uint16_t*)(data + begin_ip + 10) =
            ip_fast_csum(data + begin_ip, 5);
    }

    return 0;
}

static int txf_dest_ip_inc(int port)
{
    int begin_ip = get_end_l2(port);
    char *data;
    port_setup_t *port_tx;

    port_tx = port_setup + port;
    data = port_tx->output_data;

    if (cvmx_unlikely(port_setup[port].dest_ip_inc))
    {
        int64_t p = *(uint32_t*)(data + begin_ip + 16);
        p += port_setup[port].dest_ip_inc;
        if (p < port_setup[port].dest_ip_min)
            p = port_setup[port].dest_ip_max;
        else if (p > port_setup[port].dest_ip_max)
            p = port_setup[port].dest_ip_min;
        *(uint32_t*)(data + begin_ip + 16) = p;

        /* IP checksum */
        data[begin_ip + 10] = 0;
        data[begin_ip + 11] = 0;
        *(uint16_t*)(data + begin_ip + 10) =
            ip_fast_csum(data + begin_ip, 5);
    }

    return 0;
}

static int txf_src_port_inc_v6(int port)
{
    int begin_ip = get_end_l2(port);
    char *data;
    port_setup_t *port_tx;

    port_tx = port_setup + port;
    data = port_tx->output_data;

    if (cvmx_unlikely(port_setup[port].src_port_inc))
    {
        int p = *(uint16_t*)(data + begin_ip + 40);
        p += port_setup[port].src_port_inc;
        if (p < port_setup[port].src_port_min)
            p = port_setup[port].src_port_max;
        else if (p > port_setup[port].src_port_max)
            p = port_setup[port].src_port_min;
        *(uint16_t*)(data + begin_ip + 40) = p;
    }

    return 0;
}

static int txf_dest_port_inc_v6(int port)
{
    int begin_ip = get_end_l2(port);
    char *data;
    port_setup_t *port_tx;

    port_tx = port_setup + port;
    data = port_tx->output_data;

    if (cvmx_unlikely(port_setup[port].dest_port_inc))
    {
        int p = *(uint16_t*)(data + begin_ip + 40 + 2);
        p += port_setup[port].dest_port_inc;
        if (p < port_setup[port].dest_port_min)
            p = port_setup[port].dest_port_max;
        else if (p > port_setup[port].dest_port_max)
            p = port_setup[port].dest_port_min;
        *(uint16_t*)(data + begin_ip + 40 + 2) = p;
    }

    return 0;
}

static int txf_src_ip_inc_v6(int port)
{
    int begin_ip = get_end_l2(port);
    char *data;
    port_setup_t *port_tx;

    port_tx = port_setup + port;
    data = port_tx->output_data;

    if (cvmx_unlikely(port_setup[port].src_ip_inc))
    {
        int64_t p = *(uint64_t*)(data+begin_ip+8+8);
        p += port_setup[port].src_ip_inc;
        if (p < port_setup[port].src_ip_min)
            p = port_setup[port].src_ip_max;
        else if (p > port_setup[port].src_ip_max)
            p = port_setup[port].src_ip_min;
        *(uint64_t*)(data+begin_ip+8+8) = p;
    }

    return 0;
}

static int txf_dest_ip_inc_v6(int port)
{
    int begin_ip = get_end_l2(port);
    char *data;
    port_setup_t *port_tx;

    port_tx = port_setup + port;
    data = port_tx->output_data;

    if (cvmx_unlikely(port_setup[port].dest_ip_inc))
    {
        int64_t p = *(uint64_t*)(data+begin_ip+8+24);
        p += port_setup[port].dest_ip_inc;
        if (p < port_setup[port].dest_ip_min)
            p = port_setup[port].dest_ip_max;
        else if (p > port_setup[port].dest_ip_max)
            p = port_setup[port].dest_ip_min;
        *(uint64_t*)(data+begin_ip+8+24) = p;
    }

    return 0;
}

int txf_dest_mac_inc(int port)
{
    char *data;
    port_setup_t *port_tx;

    port_tx = port_setup + port;
    data = port_tx->output_data;

    if (cvmx_unlikely(port_setup[port].dest_mac_inc))
    {
        uint64_t m;
        char* mac = data + get_end_pre_l2(port);

        m = mac_to_uint64(mac);

        m += port_setup[port].dest_mac_inc;
        if ((m < port_setup[port].dest_mac_min) ||
	    (m > port_setup[port].dest_mac_max))
            m = port_setup[port].dest_mac_min;

        uint64_to_mac(m, mac);
    }

    return 0;
}

int txf_src_mac_inc(int port)
{
    char *data;
    port_setup_t *port_tx;

    port_tx = port_setup + port;
    data = port_tx->output_data;

    if (cvmx_unlikely(port_setup[port].src_mac_inc))
    {
        uint64_t m;
        char* mac = data + get_end_pre_l2(port) + MAC_ADDR_LEN;

        m = mac_to_uint64(mac);
        m += port_setup[port].src_mac_inc;
        if ((m < port_setup[port].src_mac_min) ||
	    (m > port_setup[port].src_mac_max))
            m = port_setup[port].src_mac_min;

        uint64_to_mac(m, mac);
    }

    return 0;
}

tx_task_t tgpio_get_txf_ip(int port, int is_src, int is_ipaddr)
{
    switch(port_setup[port].output_packet_type)
    {
        case PACKET_TYPE_HELP:
        case PACKET_TYPE_IPV4_UDP:
        case PACKET_TYPE_IPV4_TCP:
	    if (is_src)
	        if (is_ipaddr)
		    return txf_src_ip_inc;
		else
		    return txf_src_port_inc;
	    else
	        if (is_ipaddr)
		    return txf_dest_ip_inc;
		else
		    return txf_dest_port_inc;
	break;

        case PACKET_TYPE_IPV6_UDP:
        case PACKET_TYPE_IPV6_TCP:
	    if (is_src)
	        if (is_ipaddr)
		    return txf_src_ip_inc_v6;
		else
		    return txf_src_port_inc_v6;
	    else
	        if (is_ipaddr)
		    return txf_dest_ip_inc_v6;
		else
		    return txf_dest_port_inc_v6;
	break;

        case PACKET_TYPE_802_3_PAUSE:
        case PACKET_TYPE_CBFC_PAUSE:
        case PACKET_TYPE_CJPAT:
	default:
            break;
    }

    return NULL;
}

/**
 * Called every packet to increment parts of the packet as necessary.
 *
 * @param port
 * @param data
 */
static inline void tgpio_perform_tx_tasks(int port)
{
    int i;

    for (i = 0; i < port_setup[port].tx_ntasks; i++)
        if (port_setup[port].tx_tasks[i])
	    port_setup[port].tx_tasks[i](port);
}

int tgpio_packet_transmitter(const int port, const uint64_t queue,
    cvmx_pko_command_word0_t *pko_cmd, cvmx_buf_ptr_t *hw_buffer,
    uint64_t *output_cycle,  uint64_t *pcount)
{
    port_setup_t *port_tx;

    port_tx = port_setup + port;

    if (cvmx_likely(port_tx->port_valid && port_tx->output_enable &&
        port_tx->output_cycle_gap))
    {
        if (cvmx_likely(cvmx_get_cycle() << CYCLE_SHIFT >= *output_cycle))
	{
	    cvmx_pko_send_packet_prepare(port, queue, CVMX_PKO_LOCK_NONE);
	    tgpio_perform_tx_tasks(port);
	    *output_cycle += port_tx->output_cycle_gap;
	    pko_cmd->s.total_bytes = port_tx->output_packet_size +
	        get_size_pre_l2(port);
	    if (port_tx->do_checksum)
	        pko_cmd->s.ipoffp1 = get_end_l2(port) + 1;
	    else
	        pko_cmd->s.ipoffp1 = 0;

	    cvmx_pko_send_packet_finish(port, queue, *pko_cmd, *hw_buffer,
	        CVMX_PKO_LOCK_NONE);

	    /*
	     * If we aren't keeping up, start send 4 more packets per iteration
	     */
            if (cvmx_unlikely
	        (cvmx_get_cycle() << CYCLE_SHIFT > *output_cycle + 500) &&
		(*pcount > 4))
            {
                uint64_t words[8] = {
		    pko_cmd->u64, hw_buffer->u64,
		    pko_cmd->u64, hw_buffer->u64,
		    pko_cmd->u64, hw_buffer->u64,
		    pko_cmd->u64, hw_buffer->u64
		};
                *output_cycle += port_tx->output_cycle_gap * 4;
                *pcount -= 4;
                if (cvmx_likely(
		    cvmx_cmd_queue_write(CVMX_CMD_QUEUE_PKO(queue), 0, 8, words)
		    == CVMX_CMD_QUEUE_SUCCESS))
                    cvmx_pko_doorbell(port, queue, 8);
	    }

            if (cvmx_unlikely(--(*pcount) == 0))
            {
                port_tx->output_enable = 0;
                *pcount = port_tx->output_count;
                CVMX_SYNCW;
            }
            return 1; /* we've sent sth */
	}
    }
    else
    {
        *output_cycle = cvmx_get_cycle() << CYCLE_SHIFT;
	*pcount = port_tx->output_count;
    }

    return 0;
}
