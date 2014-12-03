#include <stdio.h>
#include <inttypes.h> 

#include "cvmx.h"
#include "cvmx-fpa.h"
#include "cvmx-ipd.h"
#include "cvmx-pko.h"

#define CORE_MASK_BARRIER_SYNC cvmx_coremask_barrier_sync(&(sysinfo->core_mask))
#define NUM_PACKET_BUFFERS 1024
#define PAYLOAD_OFFSET 14 // offset into Ethernet packet to reach payload
#define PAYLOAD_SIZE 50
#define PORT 2624

CVMX_SHARED cvmx_sysinfo_t *sysinfo;
CVMX_SHARED uint64_t cpu_clock_hz;
CVMX_SHARED uint64_t packet_pool;
CVMX_SHARED uint64_t wqe_pool;

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

/**
 * Fill the given buffer with an Ethernet packet whose payload is filled
 * with enough random bytes to reach the given payload size.
 *
 * @param buf           Destination buffer to which to write the packet
 * @param payload_size  Size of the packet payload (in bytes)
 *
 * @return pointer to the first byte past the end of the packet 
 */
uint8_t * build_packet(uint8_t *buf, int payload_size)
{
    int i;
    uint8_t rand_num;
    uint64_t src_mac, dest_mac;
    
    src_mac  = get_mac(sysinfo->mac_addr_base);
    dest_mac = get_mac(sysinfo->mac_addr_base) + 1;

    /* Ethernet dest address */
    for (i = 0; i < 6; i++)
      *buf++ = (dest_mac>>(40-i*8)) & 0xff;

    /* Ethernet source address */
    for (i = 0; i < 6; i++)
      *buf++ = (src_mac>>(40-i*8)) & 0xff;

    /* Ethernet Protocol */
    *buf++ = 0x08; 
    *buf++ = 0x00;

    printf("Payload bytes sent: ");
    /* Fill the payload of the packet with random bytes */
    for (i = 0; i < payload_size; i++) {
      rand_num = (uint8_t) rand();
      *buf++ = rand_num;
      printf("%x", rand_num);
    }
    printf("\n");

    /* return pointer to the end of the packet */
    return buf;
}

/* IN PROGRESS */
void send_packet()
{
  uint8_t *buf, *pbuf; 
  uint64_t queue;
  cvmx_pko_command_word0_t pko_command;
  cvmx_pko_return_value_t status;
  cvmx_buf_ptr_t hw_buffer;

  buf = (uint8_t *) cvmx_fpa_alloc(packet_pool);
  pbuf = build_packet(buf, PAYLOAD_SIZE);

  pko_command.u64 = 0;
  pko_command.s.segs = 1;
  pko_command.s.total_bytes = pbuf - buf;

  hw_buffer.s.addr = cvmx_ptr_to_phys(buf);
  hw_buffer.s.pool = packet_pool;
  hw_buffer.s.i = 0;
  hw_buffer.s.size = pbuf - buf;

  queue = cvmx_pko_get_base_queue(PORT);

  cvmx_pko_send_packet_prepare(PORT, queue, CVMX_PKO_LOCK_NONE);

  // THROWS EXCEPTION HERE
  status = cvmx_pko_send_packet_finish(PORT, queue, pko_command, hw_buffer, CVMX_PKO_LOCK_NONE);

  if (status == CVMX_PKO_SUCCESS) {
    printf("Succesfully sent packet!\n");
    cvmx_fpa_free(buf, packet_pool, 0);
  }
}

/* IN PROGRESS */
void receive_packet()
{
  cvmx_wqe_t *work = NULL;
  uint8_t *ptr;
  int i;

  printf("Waiting for packet...\n");

  while (!work) {
    /* In standalone CVMX, we have nothing to do if there isn't work,
     * so use the WAIT flag to reduce power usage. */
    work = cvmx_pow_work_request_sync(CVMX_POW_WAIT);
  }

  ptr = (uint8_t *) cvmx_phys_to_ptr(work->packet_ptr.s.addr);
  ptr += PAYLOAD_OFFSET;

  // print out the payload bytes of the recieved packet
  printf("Payload bytes recv: ");
  for (i = 0; i < PAYLOAD_SIZE; i++) {
    printf("%x", *(ptr++));
  }
}

void print_debug_info()
{
  printf("Packet pool id: %" PRIu64 "\n", packet_pool);
  printf("WQE    pool id: %" PRIu64 "\n", wqe_pool);
  printf("Packet pool block size: %" PRIu64 "\n", cvmx_fpa_get_block_size(packet_pool));
  printf("WQE    pool block size: %" PRIu64 "\n", cvmx_fpa_get_block_size(wqe_pool));
}

int init_tasks(int num_packet_buffers)
{
  /* allocate pools for packet and WQE pools and set up FPA hardware */
  if (cvmx_helper_initialize_fpa(num_packet_buffers, num_packet_buffers, CVMX_PKO_MAX_OUTPUT_QUEUES * 4, 0, 0))
    return -1;

  if (cvmx_helper_initialize_sso(num_packet_buffers))
    return -1;

  cvmx_pko_initialize_global();

  return cvmx_helper_initialize_packet_io_global();
}

int main(int argc, char *argv[])
{
  /* mandatory function to initialize simple executive application */
  cvmx_user_app_init();

  sysinfo = cvmx_sysinfo_get();

  if (cvmx_is_init_core()) {
    /* may need to specify this manually for simulator */
    cpu_clock_hz = sysinfo->cpu_clock_hz;

    if(init_tasks(NUM_PACKET_BUFFERS) != 0) {
      printf("Initialization failed!\n");
      exit(-1);
    }

    /* get the FPA pool number of packet and WQE pools */
    packet_pool = cvmx_fpa_get_packet_pool();
    wqe_pool = cvmx_fpa_get_wqe_pool();

    print_debug_info();
  }

  /* Wait (stall) until all cores in the given coremask have reached this
   * point in the progam execution before proceeding. */
  CORE_MASK_BARRIER_SYNC; 

  if (cvmx_is_init_core()) {
    receive_packet();  
  } else if (cvmx_get_core_num() == 1) {
    send_packet();
  } else { /* for this program, all cores besides the first two are superfluous */
    printf("Superfluous core #%02d\n", cvmx_get_core_num());
    return 0;
  }

  printf("Execution complete for core #%02d\n", cvmx_get_core_num());
  return 0;
}
