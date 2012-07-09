#ifndef _CPIMAGE_H_
#define _CPIMAGE_H_

#include <sys/socket.h>
#include <sys/un.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <linux/unistd.h>
#include <linux/termios.h>
#include <signal.h>

#include "list.h"
#include "cplayout.h"

#define IMAGE_VERSION 0x03

#define ACTION_LOAD		0x01
#define ACTION_PRINT		0x02
#define ACTION_LOADPRINT	0x03

#define GET_LIBRARIES_TOO          0x01
#define GET_OPEN_FILE_CONTENTS     0x02

/* Constants for cp_chunk.type */
#define CP_CHUNK_HEADER		0x01
#define CP_CHUNK_MISC		0x02
#define CP_CHUNK_REGS		0x03
#define CP_CHUNK_I387_DATA	0x04
#define CP_CHUNK_TLS		0x05
#define CP_CHUNK_FD		0x06
#define CP_CHUNK_VMA		0x07
#define CP_CHUNK_SIGHAND	0x08
#define CP_CHUNK_FINAL		0x09

#define CP_CHUNK_MAGIC		0xC0DE

/* Constants for cp_fd.type */
#define CP_CHUNK_FD_FILE	0x01
#define CP_CHUNK_FD_CONSOLE	0x02
#define CP_CHUNK_FD_SOCKET	0x03
#define CP_CHUNK_FD_FIFO	0x04
#define CP_CHUNK_FD_MAXFD	0x05

struct cp_header {
    int am_leader;
    int clone_flags;
    pid_t pid, tid, pgid, sid;
    uid_t uid;
    gid_t gid;
    int n_children;
    off_t *children_offsets;
};

struct cp_misc {
    char *cmdline;
    char *cwd;
    char *env;
};

struct cp_regs {
    struct user *user_data;
    void *opaque; /* For arch-specific data */
    int stopped;
};

#ifdef __i386__
struct cp_i387_data {
    struct user_i387_struct* i387_data;
};

struct cp_tls {
    struct user_desc* u;
};
#endif

struct cp_vma {
    unsigned long start, length;
    int prot;
    int flags;
    int dev;
    long pg_off;
    int inode;
    char *filename;
    char have_data;
    char is_heap;
    unsigned int checksum;
    void* data; /* length end-start */ /* in file, simply true if is data */
};

struct cp_sighand {
    int sig_num;
    struct k_sigaction *ksa;
};

struct cp_console {
    struct termios termios;
};

struct cp_file {
    char *filename;
    char *contents;
    int deleted;
    int size;
};

struct cp_socket_tcp {
    struct sockaddr_in sin;
    void *ici; /* If the system supports tcpcp. */
};

struct cp_socket_udp {
    struct sockaddr_in sin;
};

struct cp_socket_unix {
    int type, listening;
    struct sockaddr_un sockname;
    struct sockaddr_un peername;
};

struct cp_socket {
    int proto;
    union {
	struct cp_socket_tcp s_tcp;
	struct cp_socket_udp s_udp;
	struct cp_socket_unix s_unix;
    };
};

struct cp_fifo {
    pid_t target_pid;
    int self_other_fd;
};

struct cp_fd {
    int fd;
    int mode;
    int close_on_exec;
    int fcntl_status;
    off_t offset;
    int type;
    union {
	struct cp_console console;
	struct cp_file file;
	struct cp_fifo fifo;
	struct cp_socket socket;
    };
};

struct cp_chunk {
    int type;
    union {
	struct cp_misc misc;
	struct cp_regs regs;
	struct cp_fd fd;
	struct cp_vma vma;
	struct cp_sighand sighand;
#ifdef __i386__
	struct cp_i387_data i387_data;
	struct cp_tls tls;
#endif
    };
};

struct stream_ops {
    void *(*init)(int fd, int mode);
    void (*finish)(void *data);
    int (*read)(void *data, void *buf, int len);
    int (*write)(void *data, void *buf, int len);
    long (*ftell)(void *data);
    void (*dup2)(void *data, int newfd);
};
extern struct stream_ops *stream_ops;


/* cpimage.c */
void read_bit(void *fptr, void *buf, int len);
void write_bit(void *fptr, void *buf, int len);
char *read_string(void *fptr, char *buf, int maxlen);
void write_string(void *fptr, char *buf);
int read_chunk(void *fptr, int action);
void write_chunk(void *fptr, struct cp_chunk *chunk);
void write_process(int fd, struct list l);
void discard_bit(void *fptr, int length);
void get_process(pid_t pid, int flags, struct list *l, long *heap_start);
unsigned int checksum(char *ptr, int len, unsigned int start);

/* cp_header.c */
void fetch_chunk_header(void *fptr, int flags, struct list *process_image);
void read_chunk_header(void *fptr, int action);
void write_chunk_header(void *fptr, struct cp_header *data);

/* cp_misc.c */
void fetch_chunk_misc(void *fptr, int flags, struct list *process_image);
void read_chunk_misc(void *fptr, int action);
void write_chunk_misc(void *fptr, struct cp_misc *data);

/* cp_regs.c */
void fetch_chunks_regs(pid_t pid, int flags, struct list *process_image,
	int stopped);
void read_chunk_regs(void *fptr, int action);
void write_chunk_regs(void *fptr, struct cp_regs *data);

#ifdef __i386__
/* cp_i387.c */
void fetch_chunks_i387_data(pid_t pid, int flags, struct list *l);
void read_chunk_i387_data(void *fptr, int action);
void write_chunk_i387_data(void *fptr, struct cp_i387_data *data);

/* cp_tls.c */
void fetch_chunks_tls(pid_t pid, int flags, struct list *l);
void read_chunk_tls(void *fptr, int action);
void write_chunk_tls(void *fptr, struct cp_tls *data);
void install_tls_segv_handler();
extern int emulate_tls;
#endif

/* cp_fd.c */
void fetch_chunks_fd(pid_t pid, int flags, struct list *l);
void read_chunk_fd(void *fptr, int action);
void write_chunk_fd(void *fptr, struct cp_fd *data);
extern int console_fd;

/* cp_fd_console.c */
void fetch_fd_console(pid_t pid, int flags, int fd, struct cp_console *console);
void read_chunk_fd_console(void *fptr, struct cp_fd *fd, int action);
void write_chunk_fd_console(void *fptr, struct cp_fd *fd);

/* cp_fd_file.c */
void fetch_fd_file(pid_t pid, int flags, int fd, int inode, char *fd_path,
	struct cp_file *file);
void read_chunk_fd_file(void *fptr, struct cp_fd *fd, int action);
void write_chunk_fd_file(void *fptr, struct cp_file *file);

/* cp_fd_fifo.c */
void fetch_fd_fifo(pid_t pid, int flags, int fd, int inode,
	struct cp_fifo *fifo);
void read_chunk_fd_fifo(void *fptr, struct cp_fd *fd, int action);
void write_chunk_fd_fifo(void *fptr, struct cp_fifo *fifo);

/* cp_fd_socket.c */
void fetch_fd_socket(pid_t pid, int flags, int fd, int inode,
	struct cp_socket *socket);
void read_chunk_fd_socket(void *fptr, struct cp_fd *fd, int action);
void write_chunk_fd_socket(void *fptr, struct cp_socket *socket);

/* cp_vma.c */
void fetch_chunks_vma(pid_t pid, int flags, struct list *l, long *bin_offset);
void read_chunk_vma(void *fptr, int action);
void write_chunk_vma(void *fptr, struct cp_vma *data);
extern int extra_prot_flags;
extern unsigned long scribble_zone;
extern unsigned long syscall_loc;
extern unsigned long vdso_start;
extern unsigned long vdso_end;

/* cp_sighand.c */
void read_chunk_sighand(void *fptr, int action);
void write_chunk_sighand(void *fptr, struct cp_sighand *data);
void fetch_chunks_sighand(pid_t pid, int flags, struct list *l);

#endif /* _CPIMAGE_H_ */

/* vim:set ts=8 sw=4 noet: */
