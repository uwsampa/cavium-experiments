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
