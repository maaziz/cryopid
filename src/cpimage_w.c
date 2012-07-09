#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "cpimage.h"
#include "cryopid.h"
#include "list.h"


void write_bit(void *fptr, void *buf, int len)
{
    int c;

    if (len == 0)
	return;

    c = checksum(buf, len, 0);
    stream_ops->write(fptr, &c, sizeof(c));
    if (stream_ops->write(fptr, buf, len) != len)
	bail("Write error!");
}

void write_string(void *fptr, char *buf)
{
    int len = 0;
    
    if (buf)
	len = strlen(buf);
    write_bit(fptr, &len, sizeof(int));

    if (buf)
	write_bit(fptr, buf, len);
}

static void write_final_chunk(void *fptr)
{
    int magic = CP_CHUNK_MAGIC, type = CP_CHUNK_FINAL;
    write_bit(fptr, &magic, sizeof(int));
    write_bit(fptr, &type, sizeof(int));
}

void write_chunk(void *fptr, struct cp_chunk *chunk)
{
    int magic = CP_CHUNK_MAGIC;

    write_bit(fptr, &magic, sizeof(magic));
    write_bit(fptr, &chunk->type, sizeof(chunk->type));

    switch (chunk->type) {
	case CP_CHUNK_MISC:
	    write_chunk_misc(fptr, &chunk->misc);
	    break;
	case CP_CHUNK_REGS:
	    write_chunk_regs(fptr, &chunk->regs);
	    break;
	case CP_CHUNK_FD:
	    write_chunk_fd(fptr, &chunk->fd);
	    break;
	case CP_CHUNK_VMA:
	    write_chunk_vma(fptr, &chunk->vma);
	    break;
	case CP_CHUNK_SIGHAND:
	    write_chunk_sighand(fptr, &chunk->sighand);
	    break;
#ifdef __i386__
	case CP_CHUNK_I387_DATA:
	    write_chunk_i387_data(fptr, &chunk->i387_data);
	    break;
	case CP_CHUNK_TLS:
	    write_chunk_tls(fptr, &chunk->tls);
	    break;
#endif
	default:
	    bail("Unknown chunk type to write (0x%x)", chunk->type)
    }
}

void write_process(int fd, struct list l)
{
    void *fptr;
    struct item *i;

    fptr = stream_ops->init(fd, O_WRONLY);
    if (!fptr)
	bail("Unable to initialize writer.");

    for (i = l.head; i; i = i->next) {
	struct cp_chunk *cp = i->p;
	write_chunk(fptr, cp);
    }

    write_final_chunk(fptr);

    stream_ops->finish(fptr);
    debug("Written image.");
}

/* vim:set ts=8 sw=4 noet: */
