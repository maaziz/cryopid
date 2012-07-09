/*
 * Process state saver
 *   (C) 2004 Bernard Blackham <bernard@blackham.com.au>
 *
 * Licensed under a BSD-ish license.
 */


#include <sys/types.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "cryopid.h"
#include "cpimage.h"
#include "process.h"
#include "list.h"

extern struct stream_ops *stream_ops;

void usage(char* argv0)
{
    fprintf(stderr,
"Usage: %s [options] <output filename> <pid>\n"
"\n"
"This is used to suspend the state of a single running process to a\n"
"self-executing file.\n"
"\n"
"    -l      Include libraries in the image of the file for a full image.\n"
/*
"    -w <writer> Nomiate an output writer to use.\n"
"    -f      Save the contents of open files into the image.\n"
"    -c      Save children of this process as well.\n"
*/
"\n"
"This program is part of CryoPID %s. http://cryopid.berlios.de/\n",
    argv0, CRYOPID_VERSION);
    exit(1);
}

int main(int argc, char** argv)
{
    pid_t target_pid;
    struct list proc_image;
    int c;
    int flags = 0;
    int get_children = 0;
    int fd;
    long offset = 0;

    /* Parse options */
    while (1) {
	int option_index = 0;
	static struct option long_options[] = {
	    {"libraries", 0, 0, 'l'},
	    /*
	    {"files", 0, 0, 'f'},
	    {"children", 0, 0, 'c'},
	    {"writer", 1, 0, 'w'},
	    */
	    {0, 0, 0, 0},
	};

	c = getopt_long(argc, argv, "l"/*"fcw:"*/, long_options, &option_index);
	if (c == -1)
	    break;
	switch(c) {
	    case 'l':
		flags |= GET_LIBRARIES_TOO;
		break;
	    case 'f':
		flags |= GET_OPEN_FILE_CONTENTS;
		break;
	    case 'c':
		get_children = 1;
		break;
	    /*
	    case 'w':
		set_writer(optarg);
		break;
		*/
	    case '?':
		/* invalid option */
		usage(argv[0]);
		break;
	}
    }

    if (argc - optind != 2) {
	usage(argv[0]);
	return 1;
    }

    assert(stream_ops != NULL);

    target_pid = atoi(argv[optind+1]);
    if (target_pid <= 1) {
	fprintf(stderr, "Invalid pid: %d\n", target_pid);
	return 1;
    }

    list_init(proc_image);
    get_process(target_pid, flags, &proc_image, &offset);

    fd = open(argv[optind], O_CREAT|O_WRONLY|O_TRUNC, 0777);
    if (fd == -1) {
	fprintf(stderr, "Couldn't open %s for writing: %s\n", argv[optind],
	    strerror(errno));
	return 1;
    }

    write_stub(fd, offset);

    write_process(fd, proc_image);

    close(fd);

    return 0;
}

/* vim:set ts=8 sw=4 noet: */
