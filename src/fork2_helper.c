/*
 * WARNING: this file could panic kernels and eat kittens.
 *
 */

#define _LARGEFILE64_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/unistd.h>

static unsigned long get_last_pid_location()
{
	FILE *f;
	static unsigned long loc = 0x0;
	char type;
	char func_name[70];

	if (loc)
		return loc;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return 0;

	loc = 0;

	while (fscanf(f, "%lx %c %s", &loc, &type, func_name) == 3) {
		if (type == 'B' && !strcmp(func_name, "last_pid")) {
			fclose(f);
			return loc;
		}
	}
	fclose(f);
	return 0;
}

int set_last_pid(int pid)
{
	int fd;
	off64_t last_pid_loc;
	
	last_pid_loc = get_last_pid_location();
	if (!last_pid_loc)
		return -1;

	fd = open("/dev/kmem", O_RDWR|O_LARGEFILE);
	if (fd == -1)
		return -1;

	if (lseek64(fd, last_pid_loc, SEEK_SET) == -1)
		return -1;

	if (write(fd, &pid, sizeof(pid)) == -1)
		return -1;

	close(fd);

	return 0;
}

int get_last_pid()
{
	int fd, last_pid;
	off64_t last_pid_loc;
	
	last_pid_loc = get_last_pid_location();
	if (!last_pid_loc)
		return -1;

	fd = open("/dev/kmem", O_RDONLY|O_LARGEFILE);
	if (fd == -1)
		return -1;

	if (lseek64(fd, (off64_t)get_last_pid_location(), SEEK_SET) == -1)
		return -1;

	if (read(fd, &last_pid, sizeof(last_pid)) == -1)
		return -1;

	close(fd);

	return last_pid;
}

int main(int argc, char **argv)
{
	int want_pid;
	if (argc == 3 && strcmp(argv[0], "farewell") == 0 &&
			strcmp(argv[1], "kitty") == 0) {
		char *endptr;

		/* Need root */
		if (geteuid() != 0)
			return 3;

		want_pid = strtol(argv[2], &endptr, 10);
		if (*endptr == '\0') {
			/* Success! Do it. */
#if 0
			if ((pid_t old_last_pid = get_last_pid()) == (pid_t)-1) {
				perror("get_last_pid");
				return 2;
			}
#endif
			if (set_last_pid(want_pid-1) == -1) {
				perror("set_last_pid");
				return 2;
			}
			return 0;
		}
	}
	/* Usage error. */
	fprintf(stderr, "This program is a helper for CryoPID and should not be called directly.\n");
	return 1;
}
