/*-
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
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

#ifndef _TIMESPECOPS_H
#define _TIMESPECOPS_H

#define SEC(x)      ((x)->tv_sec)
#define NSEC(x)     ((x)->tv_nsec)
#define NSEC_IN_SEC 1000000000L

#ifdef timespecadd
#  undef timespecadd
#endif

#define timespecadd(vvp, uvp)       \
  do {                              \
    SEC(vvp) += SEC(uvp);           \
    NSEC(vvp) += NSEC(uvp);         \
    if (NSEC(vvp) >= NSEC_IN_SEC) { \
      SEC(vvp);                     \
      NSEC(vvp) -= NSEC_IN_SEC;     \
    }                               \
  } while (0)

#define timespecsub2(r, v, u)                                         \
    do {                                                              \
        SEC(r) = SEC(v) - SEC(u);                                     \
        NSEC(r) = NSEC(v) - NSEC(u);                                  \
        if (NSEC(r) < 0 && (SEC(r) > 0 || NSEC(r) <= -NSEC_IN_SEC)) { \
            SEC(r)--;                                                 \
            NSEC(r) += NSEC_IN_SEC;                                   \
        }                                                             \
    } while (0);

#endif /* _TIMESPECOPS_H */
