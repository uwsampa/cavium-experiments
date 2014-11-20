#include <stdio.h>
#include <inttypes.h> 

#include "cvmx.h"
#include "cvmx-fpa.h"
#include "cvmx-ipd.h"
#include "cvmx-pko.h"

#define CORE_MASK_BARRIER_SYNC cvmx_coremask_barrier_sync(&(sysinfo->core_mask))
#define NUM_PACKET_BUFFERS 1024

CVMX_SHARED uint64_t cpu_clock_hz;
CVMX_SHARED uint64_t packet_pool;
CVMX_SHARED uint64_t wqe_pool;

/* IN PROGRESS */
void send_packet()
{
}

/* IN PROGRESS */
void receive_packet()
{
  printf("Waiting for packet...\n");

  cvmx_wqe_t *work = NULL;
  while (!work) {
    /* In standalone CVMX, we have nothing to do if there isn't work,
     * so use the WAIT flag to reduce power usage. */
    cvmx_wqe_t *work = cvmx_pow_work_request_sync(CVMX_POW_WAIT);
  }

  printf("Received packet!\n");
}

void print_debug_info()
{
  printf("Packet pool id: %" PRIu64 "\n", packet_pool);
  printf("WQE    pool id: %" PRIu64 "\n", wqe_pool);
  printf("Packet pool block size: %" PRIu64 "\n", cvmx_fpa_get_block_size(packet_pool));
  printf("WQE    pool block size: %" PRIu64 "\n", cvmx_fpa_get_block_size(wqe_pool));
}

int main(int argc, char *argv[])
{
  cvmx_sysinfo_t *sysinfo;

  /* mandatory function to initialize simple executive application */
  cvmx_user_app_init();

  sysinfo = cvmx_sysinfo_get();

  if (cvmx_is_init_core()) {
    /* may need to specify this manually for simulator */
    cpu_clock_hz = sysinfo->cpu_clock_hz;

    /* allocate pools for packet and WQE pools and set up FPA hardware */
    if (cvmx_helper_initialize_fpa(NUM_PACKET_BUFFERS, NUM_PACKET_BUFFERS, CVMX_PKO_MAX_OUTPUT_QUEUES * 4, 0, 0) == 0) {
      printf("FPA initialization failed!\n");
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
