Author: Teddy Brow

In its current state, this program is meant to be run on exactly two cores
(i.e. coremask=0x3)

Code is largely borrowed from the passthrough and traffic-gen examples
included with the SDK.

Currently, the source and executable are still named "passthrough" since I
couldn't seem to properly modify the Makefile to accomodate a name-change.
On a similar note, the Makefile contains a lot of unecessary junk that is a
holdover from when it was initially copied from the passthrough example. In
the future I should be able to change this, but as things are now, I can't
seem to create a working Makefile for anything more than the absolute
simplest of programs...

TL;DR - Just focus on the code in passthrough.c . Everything else contained
here is just a means to the end of getting the damn thing built.

=================

Further notes on current state of this program and issues:

Using my send_packet and receive_packet functions, I am able to send and
receive a single packet, and the latency is reported as about 15 microseconds.
This is a larger latency than we would expect. My next step was to try to send
and recieve multiple packets to reduce the effect of any "warm-up" overhead on
the results. Unfortunately, while I am apparently able to send multiple
packets, I'm only ever able to receive the first one. I have not been able to
find a fix to this issue.

Regarding the single packet latency, it may be that my timing implementation
is improper. I'm computing the elapsed time based on the change in CPU cycle
count and converting to microseconds, but I'm assigning the initial and final
cycle counts on different cores, which could possibly be a source of error. I
haven't been able to verify or deny this, however. A better implementation
would probalby make use of the board's dedicated hardware timers.
