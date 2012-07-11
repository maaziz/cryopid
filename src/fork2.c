#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* FIXME: so unbelievably racy. */
int fork2(pid_t pid)
{
	extern char** environ;
	pid_t helper_pid;
	int status;

	if (kill(pid, 0) != -1 || errno != ESRCH) {
		errno = EEXIST;
		return -1;
	}

	switch (helper_pid = fork()) {
		case -1:
			return -1;
		case 0: /* parent */
			if (waitpid(helper_pid, &status, 0) == -1)
				return -1;
			if (WIFEXITED(status)) {
				switch (WEXITSTATUS(status)) {
					case 0:
						return 0;
					case 2:
						errno = ENXIO;
						return -1;
					case 3:
						errno = EPERM;
						return -1;
					case 50:
						fprintf(stderr, "Could not find fork2_helper\n");
						errno = ENOENT;
						return -1;
				}
			} else
				return -1;
		default: /* child */
			{
				char *argv[] = {"farewell", "kitty", "XXXXXXXXXX", NULL};
				snprintf(argv[2], 10, "%d", pid);
#ifndef FORK2HELPER
#define FORK2HELPER "fork2_helper"
#endif
				execve(FORK2HELPER, argv, environ);
#undef FORK2HELPER
				perror("execve");
				_exit(50);
			}
	}
	return fork();
}
