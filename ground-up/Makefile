ifndef OCTEON_ROOT
OCTEON_ROOT = ../..
endif

#  default target
default: application-target

#  standard common Makefile fragment
include $(OCTEON_ROOT)/common.mk

#  include relevant component Makefile fragments
dir := $(OCTEON_ROOT)/executive
include $(dir)/cvmx.mk

#  application specification
TARGET = ground-up$(PREFIX)
OBJS = $(OBJ_DIR)/ground-up.o
CFLAGS_LOCAL = -g -O2 -W -Wall -Wno-unused-parameter
$(OBJ_DIR)/ground-up.o: ground-up.c
	${COMPILE}
include $(OCTEON_ROOT)/application.mk

clean:
	rm -f $(TARGET)
	rm -fr $(OBJ_DIR)
