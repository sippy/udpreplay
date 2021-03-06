/*
 * Copyright (c) 1992 Regents of the University of California.
 * All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <stdint.h>

#include "network.h"

#if !defined(BYTE_ORDER)
# error "BYTE_ORDER needs to be defined"
#endif

/*
 * Checksum routine for Internet Protocol family headers.
 */
uint16_t
my_in_cksum(void *p, int len)
{
    int sum = 0, oddbyte = 0, v = 0;
    u_char *cp = reinterpret_cast<u_char *>(p);

    /* we assume < 2^16 bytes being summed */
    while (len > 0) {
        if (oddbyte) {
            sum += v + *cp++;
            len--;
        }
        if (((long)cp & 1) == 0) {
            while ((len -= 2) >= 0) {
                sum += *(u_short *)cp;
                cp += 2;
            }
        } else {
            while ((len -= 2) >= 0) {
#if BYTE_ORDER == BIG_ENDIAN
                sum += *cp++ << 8;
                sum += *cp++;
#else
                sum += *cp++;
                sum += *cp++ << 8;
#endif
            }
        }
        if ((oddbyte = len & 1) != 0) {
#if BYTE_ORDER == BIG_ENDIAN
            v = *cp << 8;
#else
            v = *cp;
#endif
        }
    }
    if (oddbyte)
        sum += v;
    sum = (sum >> 16) + (sum & 0xffff); /* add in accumulated carries */
    sum += sum >> 16;               /* add potential last carry */
    return (0xffff & ~sum);
}
