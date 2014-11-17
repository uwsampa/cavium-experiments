#include <stdio.h>
#include <string.h>
#include <inttypes.h> 

#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-spinlock.h"
#include "cvmx-fpa.h"
#include "cvmx-ilk.h"
#include "cvmx-pip.h"
#include "cvmx-ipd.h"
#include "cvmx-pko.h"
#include "cvmx-dfa.h"
#include "cvmx-pow.h"
#include "cvmx-sysinfo.h"
#include "cvmx-coremask.h"
#include "cvmx-bootmem.h"
#include "cvmx-helper.h"
#include "cvmx-app-hotplug.h"
#include "cvmx-helper-cfg.h"
#include "cvmx-srio.h"
#include "cvmx-config-parse.h"

#define CORE_MASK_BARRIER_SYNC cvmx_coremask_barrier_sync(&coremask_passthrough)
#define FAU_ERRORS      ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 8))   /* Fetch and add for counting detected errors */
#define IS_INIT_CORE cvmx_is_init_core()
#define PORT 2624

CVMX_SHARED uint64_t       packet_sent_clk_cnt;
CVMX_SHARED int            clock_in_use; 
CVMX_SHARED uint64_t       cpu_clock_hz;
CVMX_SHARED cvmx_sysinfo_t *sysinfo;

static unsigned int packet_termination_num;

/**
 * Setup the Cavium Simple Executive Libraries using defaults
 *
 * @param num_packet_buffers -> number of outstanding packets to support
 *
 * @return zero on success
 */
static int application_init_simple_exec(int num_packet_buffers)
{
    int result;

    if (cvmx_helper_initialize_fpa(num_packet_buffers, num_packet_buffers, CVMX_PKO_MAX_OUTPUT_QUEUES * 4, 0, 0))
        return -1;

    if (cvmx_helper_initialize_sso(num_packet_buffers))
        return -1;

    cvmx_helper_cfg_opt_set(CVMX_HELPER_CFG_OPT_USE_DWB, 0);
    result = cvmx_helper_initialize_packet_io_global();

    cvmx_helper_setup_red(num_packet_buffers/4, num_packet_buffers/8);

    /* Leave 16 bytes space for the ethernet header */
    cvmx_write_csr(CVMX_PIP_IP_OFFSET, 2);
    cvmx_helper_cfg_set_jabber_and_frame_max();
    cvmx_helper_cfg_store_short_packets_in_wqe();

    /* Initialize the FAU registers. */
    cvmx_fau_atomic_write64(FAU_ERRORS, 0);

    return result;
}

/**
 * Convert an aray of 6 bytes to a uin64_t mac address
 *
 * @param buffer  Pointer to 6 bytes in network order
 */
static inline uint64_t get_mac(uint8_t *buffer)
{
    return (((uint64_t)buffer[0] << 40) |
            ((uint64_t)buffer[1] << 32) |
            ((uint64_t)buffer[2] << 24) |
            ((uint64_t)buffer[3] << 16) |
            ((uint64_t)buffer[4] << 8) |
            ((uint64_t)buffer[5] << 0));
}

static inline char *build_packet_mac_only(char *packet, int port)
{
    int i;
    char *ptr = packet;
    uint64_t src_mac, dest_mac;
    
    src_mac  = get_mac(sysinfo->mac_addr_base);
    dest_mac = get_mac(sysinfo->mac_addr_base) + 1;

    /* Ethernet dest address */
    for (i=0; i<6; i++)
      *ptr++ = (dest_mac>>(40-i*8)) & 0xff;

    /* Ethernet source address */
    for (i=0; i<6; i++)
      *ptr++ = (src_mac>>(40-i*8)) & 0xff;

    return ptr;
}

/**
 * Generates an ethernet packet, from MAC destination address
 * to the end of the payload (i.e. generates the 9th octet
 * onward until the point where the frame check sequence begins).
 *
 * @param packet -> buffer in which to store the packet data
 * @param port   -> output port to build for
 * @param size   -> how large (in bytes) to make the payload
 */
static void build_packet(char* packet, int port, int payload_size)
{
  char *ptr = build_packet_mac_only(packet, port), *end_ptr;

  /* Ethernet Protocol */
  *ptr++ = 0x08; 
  *ptr++ = 0x00;

  end_ptr = ptr + payload_size;

  /* Fill the payload of the packet with random bytes */
  while (ptr < end_ptr) *ptr++ = rand();

  // Note: I'm ignoring the validate flag for this packet type

  return;
}

void receive_packet()
{
  uint64_t packet_rec_clk_cnt, diff;
  cvmx_wqe_t *work;

  while(!work) {
    work = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
  }

  packet_rec_clk_cnt = cvmx_clock_get_count(CVMX_CLOCK_RCLK);
  diff = packet_rec_clk_cnt - packet_sent_clk_cnt; 
  clock_in_use = 0;
  printf("\nlatency: %f microsec\n", diff / (cpu_clock_hz / 10000000.0)); 
}

void receive_many_packets(int how_many)
{
  int recv_cnt;
  uint64_t packet_rec_clk_cnt, diff;
  cvmx_wqe_t *work;

  while (recv_cnt < how_many)
  {
    work = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
    if (work) recv_cnt++;
    // TODO - Do I need to free anything here? How to "dispose of" received packet?
  }

  packet_rec_clk_cnt = cvmx_clock_get_count(CVMX_CLOCK_RCLK);
  diff = packet_rec_clk_cnt - packet_sent_clk_cnt; 
  clock_in_use = 0;
  printf("\nlatency: %f microsec\n", diff / (cpu_clock_hz / 10000000.0)); 

}

void send_packet()
{
  int port = PORT, size = 1000;
  uint64_t queue = cvmx_pko_get_base_queue(PORT); 
  char *packet = cvmx_bootmem_alloc(2000, 0);
  cvmx_buf_ptr_t hw_buffer;
  cvmx_pko_command_word0_t pko_command;

  build_packet(packet, port, size);

  /* Build the PKO buffer pointer */
  hw_buffer.u64 = 0;
  hw_buffer.s.pool = CVMX_FPA_PACKET_POOL;
  hw_buffer.s.size = 0xffff;
  hw_buffer.s.back = 0;
  hw_buffer.s.addr = cvmx_ptr_to_phys(packet);

  /* Build the PKO command */
  pko_command.u64 = 0;
  pko_command.s.dontfree =1;
  pko_command.s.segs = 1;

  cvmx_pko_send_packet_prepare(port, queue, CVMX_PKO_LOCK_NONE);
  packet_sent_clk_cnt = cvmx_clock_get_count(CVMX_CLOCK_RCLK);
  cvmx_pko_send_packet_finish(port, queue, pko_command, hw_buffer, CVMX_PKO_LOCK_NONE);
}

void send_many_packets(int how_many)
{
  int port = PORT, size = 1000, sent_cnt = 0;
  uint64_t queue = cvmx_pko_get_base_queue(PORT); 
  char *packet = cvmx_bootmem_alloc(2000, 0);
  cvmx_buf_ptr_t hw_buffer;
  cvmx_pko_command_word0_t pko_command;

  build_packet(packet, port, size);

  /* Build the PKO buffer pointer */
  hw_buffer.u64 = 0;
  hw_buffer.s.pool = CVMX_FPA_PACKET_POOL;
  hw_buffer.s.size = 0xffff; // TODO - Do I need to change this???
  hw_buffer.s.back = 0;
  hw_buffer.s.addr = cvmx_ptr_to_phys(packet);

  /* Build the PKO command */
  pko_command.u64 = 0;
  pko_command.s.dontfree =1;
  pko_command.s.segs = 1;

  packet_sent_clk_cnt = cvmx_clock_get_count(CVMX_CLOCK_RCLK);
  while (sent_cnt < how_many) {
    cvmx_pko_send_packet_prepare(port, queue, CVMX_PKO_LOCK_NONE);
    cvmx_pko_send_packet_finish(port, queue, pko_command, hw_buffer, CVMX_PKO_LOCK_NONE);
    sent_cnt++;
  }

  printf("\nDone sending %d packets.\n", sent_cnt);
}

/**
 * Main entry point
 *
 * @return exit code
 */
int main(int argc, char *argv[])
{
  struct cvmx_coremask coremask_passthrough;
  int result = 0;

  /* mandatory function to initialize the Simple Executive application */
  cvmx_user_app_init();

  /* compute coremask_passthrough on all cores for the first barrier sync below */
  sysinfo = cvmx_sysinfo_get();
  cvmx_coremask_copy(&coremask_passthrough, &sysinfo->core_mask);

  cpu_clock_hz = sysinfo->cpu_clock_hz;

  packet_termination_num = 1000;

  /* elect a core to perform boot initializations, as only one core needs to
   * perform this function. */
  if (IS_INIT_CORE) {
    if ((result = application_init_simple_exec(packet_termination_num+80)) != 0) {
        printf("Simple Executive initialization failed.\n");
        printf("TEST FAILED\n");
        return result;
    }
  }
   
  /* wait (stall) until all cores in the given coremask have reached this
   * point in the progam execution before proceeding */
  CORE_MASK_BARRIER_SYNC;

  /* does core local initialization for packet io */
  cvmx_helper_initialize_packet_io_local();
   
  CORE_MASK_BARRIER_SYNC;

  if (IS_INIT_CORE) {
    receive_packet();
  } else {
    send_packet();
  }

  CORE_MASK_BARRIER_SYNC;

  printf("\ndone\n");
  return result;
}
