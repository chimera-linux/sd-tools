# sd-tools

This is a collection of tools forked from systemd. Currently the following
are provided:

* sysusers
* tmpfiles

The goal is to provide a standalone, minimized version of some of the tools
for use in distributions that do not use systemd. It is not a portability
kludge; the codebase has undergone some heavy scrubbing to get rid of a
majority of the non-portable bits, so alternative libc implementations
and so on are properly supported.

It is currently work in progress so some parts are not entirely flexible
and other parts such as man pages are still missing.
