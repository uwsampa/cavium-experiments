ifndef OCTEON_ROOT
OCTEON_ROOT = ../..
endif

#  standard common Makefile fragment
                                                                                
include $(OCTEON_ROOT)/common.mk

CFLAGS_LOCAL = -g -O2 -W -Wall -Wno-unused-parameter -I$(OCTEON_ROOT)/target/include

TARGET = simple-test$(PREFIX)

ifeq (linux,$(findstring linux,$(OCTEON_TARGET)))
all:
	echo "simple-test: This program doesn't support Linux"
else
all: $(TARGET)
endif

$(TARGET): simple-test.c
	$(CC) -o $(TARGET) $(CFLAGS_LOCAL) $(CFLAGS_GLOBAL) simple-test.c

clean:
	rm -f $(TARGET)
