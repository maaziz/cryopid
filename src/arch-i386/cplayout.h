#ifndef _CPLAYOUT_H_
#define _CPLAYOUT_H_

#define TRAMPOLINE_ADDR		0x00800000   /* 8MB mark */

#define RESUMER_START	0x00000000 /* Lowest location resumer will be at */
#define RESUMER_END	0x00800000 /* Highest location resumer will be at */

#define TOP_OF_STACK	0x00800000

#define MALLOC_START	0x01000000 /* Here we store a pool of 32MB to use */
#define MALLOC_END	0x02000000

/* So with the above parameters, our memory map looks something like:
 *
 * RESUMER_START     code
 *                   data
 *
 *
 * TOP_OF_STACK      stack
 * RESUMER_END
 * TRAMPOLINE_ADDR
 *
 * MALLOC_START
 * MALLOC_END
 *
 * ... program stuff
 */

#endif /* _CPLAYOUT_H_ */
