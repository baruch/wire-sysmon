wire-sysmon
===========

wire-sysmon is a system monitor written in C with [libwire][libwire] and presenting a
simple web-app to display the current system status.

The main intention is to test-drive libwire and show how to work with libwire
to create an asynchronously synchronous program where most parts of the code
are written in a synchronous-like fashion without any callbacks but to have the
core code run in a single thread without blocking each part while waiting for
IO and network operations.

As opposed to [linux-dash][dash] from which it is derived there are no forks
and no execs in the process of gathering the information so the load on the
monitored server is rather minimal.

Another difference is that the speed estimate is using a packet-pair method
which is implemented in a rather simple-minded fashion and without much attempt
at accuracy but then, the speed estimate of the [linux-dash][dash] is not very
accurate either.

Some corners were cut and IPv6 support is sorely lacking.

Thanks
------

This application is derived from [linux-dash][dash] and uses the web-app side (html, js, css) unmodified.

Author
------

Baruch Even <baruch@ev-en.org>

  [libwire]: https://github.com/baruch/libwire
  [dash]: https://github.com/afaqurk/linux-dash
