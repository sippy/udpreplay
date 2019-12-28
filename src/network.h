/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2019 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _NETWORK_H_
#define _NETWORK_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Function prototypes */
uint16_t my_in_cksum(void *, int);

#ifdef __cplusplus
}
#endif

#define my_ip_chksum_start() { \
    uint32_t _wsum; \
    static const union { \
        uint8_t b8[2]; \
        uint16_t u16; \
    } _ppadv4 = {{0x0, IPPROTO_UDP}}; \
    _wsum = 0;
#define my_ip_chksum_update(dp, len) { \
    const uint16_t *ww; \
    int nleft; \
    ww = (const uint16_t *)(dp); \
    for (nleft = (len); nleft > 1; nleft -= 2)  { \
        (_wsum) += *ww++; \
    } \
}
#define my_ip_chksum_update_data(dp, len) { \
    const uint16_t *ww; \
    int nleft; \
    union { \
        uint16_t us; \
        uint8_t uc[2]; \
    } last; \
    ww = (const uint16_t *)(dp); \
    for (nleft = (len); nleft > 1; nleft -= 2)  { \
        (_wsum) += *ww++; \
    } \
    if (nleft == 1) { \
        last.uc[0] = *(const uint8_t *)ww; \
        last.uc[1] = 0; \
        (_wsum) += last.us; \
    } \
}
#define my_ip_chksum_pad_v4() my_ip_chksum_update(&(_ppadv4.u16), sizeof(_ppadv4.u16))
#define my_ip_chksum_fin(osum) \
    (_wsum) = ((_wsum) >> 16) + ((_wsum) & 0xffff); \
    (_wsum) += ((_wsum) >> 16); \
    osum = ~(_wsum); \
}

#endif
