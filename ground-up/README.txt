Author: Teddy Brow

This is my attempt to create a working program to generate, send, and receive
packets that can be built with a minimal Makefile (i.e. one without a bunch of
junk that got copied over from an example's Makefile). It will likely replace
latency-test eventually. Basically, I'm trying to take a very incrememntal
approach to write something that works and that I fully understand.

===============================

Current status of this program:

I was able to create an (initially) working program with a minimal Makefile,
but the program throws an exception whenever I try to send a packet (e.g.
when calling cvmx_pko_send_packet_finish). I have not been able to resolve
this issue. See exception-output.txt for details on the exception thrown.
