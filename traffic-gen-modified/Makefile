######################*license start*###################################
#   Copyright (c) 2003-2008 Cavium Inc. (support@cavium.com). All rights
#   reserved.
#
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following
#         disclaimer in the documentation and/or other materials provided
#         with the distribution.
#
#       * Neither the name of Cavium Inc. nor the names of
#         its contributors may be used to endorse or promote products
#         derived from this software without specific prior written
#         permission.
#
#   TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
#   AND WITH ALL FAULTS AND CAVIUM NETWORKS MAKES NO PROMISES, REPRESENTATIONS
#   OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
#   RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
#   REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
#   DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES
#   OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR
#   PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET
#   POSSESSION OR CORRESPONDENCE TO DESCRIPTION.  THE ENTIRE RISK ARISING OUT
#   OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
#
#
#   For any questions regarding licensing please contact marketing@cavium.com
#

#
# File version info: $Id: Makefile 90106 2013-11-02 00:30:46Z cchavva $


ifndef OCTEON_ROOT
OCTEON_ROOT = ../..
endif

ifeq (${OCTEON_MODEL},OCTEON_CN30XX)
all:
	@echo "traffic-gen: This example requires multiple cores and is not supported on CN30xx"
else

all: application-target

endif

#  standard common Makefile fragment

include $(OCTEON_ROOT)/common.mk

#  include relevant component Makefile fragments

dir := $(OCTEON_ROOT)/executive
include $(dir)/cvmx.mk

#  application specification

TARGET = traffic-gen$(PREFIX)

CFLAGS_LOCAL = -g -O3 -W -Wall -Wno-unused-parameter
CFLAGS_LOCAL += -I${OCTEON_ROOT}/bootloader/u-boot/include/asm/arch
ifeq ($(cfg_lang),no)
	TARGET = traffic-gen_no_cfg$(PREFIX)
	OBJS = $(OBJ_DIR)/traffic-gen_no_cfg.o $(OBJ_DIR)/traffic-gen-pktio.o
$(OBJ_DIR)/traffic-gen_no_cfg.o: traffic-gen.c
	${COMPILE}
else
	CFLAGS_LOCAL += -DENABLE_USING_CONFIG_STRING
	OBJS = $(OBJ_DIR)/traffic-gen.o $(OBJ_DIR)/traffic-gen-pktio.o
endif

include $(OCTEON_ROOT)/application.mk

clean:
	rm -f $(TARGET)
	rm -fr $(OBJ_DIR)
	rm -f $(CVMX_CONFIG)

.PHONY: flash
flash: ${TARGET}
	mount /mnt/cf1
	mipsisa64-octeon-elf-strip -o /mnt/cf1/traffic-gen ${TARGET}

.PHONY: tftp
tftp: ${TARGET}
	mipsisa64-octeon-elf-strip -o /tftpboot/traffic-gen ${TARGET}

