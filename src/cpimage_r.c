#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "cpimage.h"
#include "cryopid.h"
#include "list.h"


void read_bit(void *fptr, void *buf, int len)
{
    int rlen;
    int c1, c2;

    if (len == 0)
	return;

    stream_ops->read(fptr, &c1, sizeof(c1));
    rlen = stream_ops->read(fptr, buf, len);
    if (rlen != len)
	bail("Read error (wanted %d bytes, got %d)!", len, rlen);
    c2 = checksum(buf, len, 0);
    if (c1 != c2)
	debug("CHECKSUM MISMATCH (len %d): should be 0x%x, measured 0x%x",
		len, c1, c2);
}

void discard_bit(void *fptr, int length)
{
    static char null[4096];
    int remaining;

    if (length == 0)
	return;

    stream_ops->read(fptr, null, sizeof(unsigned int));
    remaining = length;
    while (remaining > 0) {
	int len = sizeof(null);
	if (len > remaining)
	    len = remaining;
	remaining -= stream_ops->read(fptr, null, len);
    }
}

char *read_string(void *fptr, char *buf, int maxlen)
{
    /* maxlen is ignored if it is 0 */
    int len;

    read_bit(fptr, &len, sizeof(int));

    if (maxlen && len > maxlen) /* We don't cater for this */
	bail("String longer than expected!");

    if (!buf)
	buf = malloc(len+1);

    read_bit(fptr, buf, len);
    buf[len] = '\0';

    return buf;
}

int read_chunk(void *fptr, int action)
{
    int magic, type;
    
    if (action & ACTION_PRINT)
	fprintf(stderr, "[%8lx] ", stream_ops->ftell(fptr));

    read_bit(fptr, &magic, sizeof(magic));
    if (magic != CP_CHUNK_MAGIC)
	bail("Invalid magic in chunk header (0x%x)!", magic);

    read_bit(fptr, &type, sizeof(type));

    switch (type) {
	case CP_CHUNK_HEADER:
	    read_chunk_header(fptr, action);
	    break;
	case CP_CHUNK_MISC:
	    read_chunk_misc(fptr, action);
	    break;
	case CP_CHUNK_REGS:
	    read_chunk_regs(fptr, action);
	    break;
	case CP_CHUNK_FD:
	    read_chunk_fd(fptr, action);
	    break;
	case CP_CHUNK_VMA:
	    read_chunk_vma(fptr, action);
	    break;
	case CP_CHUNK_SIGHAND:
	    read_chunk_sighand(fptr, action);
	    break;
#ifdef __i386__
	case CP_CHUNK_I387_DATA:
	    read_chunk_i387_data(fptr, action);
	    break;
	case CP_CHUNK_TLS:
	    read_chunk_tls(fptr, action);
	    break;
#endif
	case CP_CHUNK_FINAL:
	    if (action & ACTION_PRINT)
		fprintf(stderr, "End of process image.\n");
	    return 0;
	default:
	    bail("Unknown chunk type read (0x%x)", type)
    }

    if (action & ACTION_PRINT)
	fprintf(stderr, "\n");

    return 1;
}

/* vim:set ts=8 sw=4 noet: */
