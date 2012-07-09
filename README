CryoPID 0.5.9.1

    (C) 2004-2005 Bernard Blackham
    See LICENSE file for licensing details

OVERVIEW
--------
CryoPID allows you to capture the state of a running process in Linux and save
it to a file. This file can then be used to resume the process later on, either
after a reboot or even on another machine.

The advantages of CryoPID over other checkpointing systems available for Linux
is that is does not require any prior thought in order to use it on a process.
Binaries do not need modification or special loading procedures. The
checkpointed binary need not be killed either.

COMPILING
---------

To compile CryoPID, run:
  $ cd src
  $ make

This should create a program called "freeze", which is the only binary required.

RUNNING
-------
Then to freeze a process, run:
  $ ./freeze <output filename> <pid>

For example,
  $ ./freeze test 6123
will freeze process 6123 and save it as a file called test.

The generated checkpoint file is a self-extracting executable containing the
image for the process.

If you are planning to use the checkpoint file in the long term, or resume on
another machine where the libraries are potentially different (they must be
precisely the same in order to resume without them), then you can pass the "-l"
flag to freeze in order to have them saved into the binary also. This may
increase the size of the executable substantially.

HELP
----
For help, e-mail the mailing list - cryopid-devel@lists.berlios.de.

For a list of what's supported in a process and what's not, the best guides are
the TODO file, and the website - http://cryopid.berlios.de/

Enjoy!
