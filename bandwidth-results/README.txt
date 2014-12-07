This folder contains the results for my bandwidth testing of the CN6800
evaluation board.

This data was collected using a modified version of the traffic-gen example
included with the OCTEON SDK. This modified program may be found in the
traffic-gen-modified directory. Search for comments containing MODIFIED to
locate my edits and additions.

To collect the data, I ran the program on the board using all 32 cores
(coremask=0xffffffff) and used the following commands once the program had
initialized:

	// Note: 2624 is the port number of the XAUI interface with a
	// physical loopback plug that I was using
	
	// change the packet type to ethernet
	tx.type 2624 ethernet

	// set the size of the ethernet packet payload to be <size> bytes
	tx.size 2624 <size>

	// find maximum transmission rate for which all packets sent out on
	// port 2624 are also received on port 2624
	find.max 2624 2624

Note that the bandwidth for each data point only takes into account payload
bytes transmitted and ignores any overhead bytes transmitted. That is, the
bandwidth listed in the results denotes how many bytes of "useful" data can
be transmitted when sending ethernet packets with the given payload size.
