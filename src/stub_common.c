#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "cryopid.h"
#include "cpimage.h"
#include "process.h"
#include "stub.h"

char tramp[100];
extern char tramp[] __attribute__((__section__((".tramp"))));
static int image_fd, real_fd;

int verbosity = 0;
int dump_only = 0;
int action = ACTION_LOAD;
int want_pid = 0;
int do_pause = 0;
int reforked = 0;

int real_argc;
char** real_argv;
char** real_environ;
extern char** environ;
#ifdef USE_GTK
extern char display_environ[80];
extern char xauthority_environ[80];
extern int gtk_can_close_displays;
#endif

static void read_process()
{
    void *fptr;

    fptr = stream_ops->init(image_fd, O_RDONLY);
    if (!fptr)
	bail("Unable to initialize reader.");

    /* Read and process all chunks. */
    while (read_chunk(fptr, action));

    /* Cleanup the input file. */
    stream_ops->finish(fptr);
    //close(console_fd);

    /* The trampoline code should now be magically loaded at 0x10000.
     * Jumping there will restore registers and continue execution.
     */

    if (!(action & ACTION_LOAD))
	exit(0);

    if (do_pause)
	sleep(2);

    jump_to_trampoline();
}

static int open_self()
{
    int fd;
    if (verbosity > 0)
	fprintf(stderr, "Reading image...\n");
    fd = open("/proc/self/exe", O_RDONLY);
    if (fd == -1) {
	fprintf(stderr, "Couldn't open self: %s\n", strerror(errno));
	exit(1);
    }
    return fd;
}

void usage(char* argv0)
{
    fprintf(stderr,
"Usage: %s [options]\n"
"\n"
"This is a saved image of a process. To resume this process, you can simply\n"
"run this executable. Some options that may be of interest when restoring\n"
"this process:\n"
"\n"
"    -d      Describe contents of file without actually restoring.\n"
"    -v      Be verbose while resuming.\n"
"    -p      Pause between steps before resuming (for debugging)\n"
"    -P      Attempt to gain original PID by way of fork()'ing a lot\n"
#ifdef USE_GTK
"    -g      Close Gtk+ displays. (Required to migrate a second time, but\n"
#endif
"            requires at least Gtk+ 2.10)\n"
"\n"
"This image was created by CryoPID %s. http://cryopid.berlios.de/\n",
    argv0, CRYOPID_VERSION);
    exit(1);
}

void real_main(int argc, char** argv) __attribute__((noreturn));
void real_main(int argc, char** argv) __attribute__((noinline));
void real_main(int argc, char** argv)
{
    image_fd = 42;
    /* See if we're being executed for the second time. If so, read arguments
     * from the file.
     */
    if (lseek(image_fd, 0, SEEK_SET) != -1) {
	safe_read(image_fd, &argc, sizeof(argc), "argc from cryopid.state");
	argv = (char**)xmalloc(sizeof(char*)*argc+1);
	argv[argc] = NULL;
	int i, len;
	for (i=0; i < argc; i++) {
	    safe_read(image_fd, &len, sizeof(len), "argv len from cryopid.state");
	    argv[i] = (char*)xmalloc(len);
	    safe_read(image_fd, argv[i], len, "new argv from cryopid.state");
	}
	close(image_fd);
	reforked = 1;
    } else {
	if (errno && errno != EBADF) {
	    /* EBADF is the only error we should be expecting! */
	    fprintf(stderr, "Unexpected error on lseek. Aborting (%s).\n",
		    strerror(errno));
	    exit(1);
	}
    }

    /* Parse options */
    while (1) {
	int option_index = 0;
	int c;
	static struct option long_options[] = {
	    {0, 0, 0, 0},
	};
	
	c = getopt_long(argc, argv, "dvpPg",
		long_options, &option_index);
	if (c == -1)
	    break;
	switch(c) {
	    case 'd':
		action &= ~ACTION_LOAD;
		action |= ACTION_PRINT;
		break;
	    case 'v':
		verbosity++;
		action |= ACTION_PRINT;
		break;
	    case 'p':
		do_pause = 1;
		break;
	    case 'P':
		want_pid = 1;
		break;
#ifdef USE_GTK
	    case 'g':
		gtk_can_close_displays = 1;
		break;
#endif
	    case '?':
		/* invalid option */
		usage(argv[0]);
		break;
	}
    }

    if (argc - optind) {
	fprintf(stderr, "Extra arguments not expected (%s ...)!\n", argv[optind]);
	usage(argv[0]);
    }

    image_fd = real_fd;
    seek_to_image(image_fd);

    read_process();

    fprintf(stderr, "Something went wrong :(\n");
    exit(1);
}

int main(int argc, char**argv, char **envp)
{
    int i;

#ifdef __x86_64__
    /* FIXME: this doesn't belong here. */
    extern void set_fs();
    set_fs();
#endif

    get_task_size();

    /* Take a copy of our argc/argv and environment below we blow them away */
    real_argc = argc;
    real_argv = (char**)xmalloc((sizeof(char*)*argc)+1);
    for(i=0; i < argc; i++)
	real_argv[i] = strdup(argv[i]);
    real_argv[i] = NULL;

    for(i = 0; envp[i]; i++); /* count environment variables */
    real_environ = xmalloc((sizeof(char*)*i)+1);
    for(i = 0; envp[i]; i++) {
	*real_environ++ = strdup(envp[i]);
#ifdef USE_GTK
	if (strncmp(envp[i], "DISPLAY=", 8) == 0) {
	    strncpy(display_environ, envp[i]+8, sizeof(display_environ)-1);
	    display_environ[sizeof(display_environ)-1] = '\0';
	} else if (strncmp(envp[i], "XAUTHORITY=", 11) == 0) {
	    strncpy(xauthority_environ, envp[i]+11, sizeof(xauthority_environ)-1);
	    xauthority_environ[sizeof(xauthority_environ)-1] = '\0';
	}
#endif
    }
    *real_environ = NULL;
    environ = real_environ;

    real_fd = open_self();
    relocate_stack();

    /* Now hope for the best! */
    real_main(real_argc, real_argv);
}

/* vim:set ts=8 sw=4 noet: */
