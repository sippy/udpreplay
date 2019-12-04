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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>

#include <iostream>
#include <system_error>

#include "pcap_save.h"
#include "recvfromto.h"
#include "network.h"

using namespace std;

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_VER_MAJR   2
#define PCAP_VER_MINR   4

#define errcat std::system_category()

PCAP_Save::PCAP_Save(const char *oname, int insock)
{
  struct pcap_file_header phead;

  memset(&phead, '\0', sizeof(phead));
  phead.magic = PCAP_MAGIC;
  phead.version_major = PCAP_VER_MAJR;
  phead.version_minor = PCAP_VER_MINR;
  phead.snaplen = 65535;
  phead.linktype = DLT_NULL;

  ofd = open(oname, O_WRONLY | O_CREAT | O_TRUNC, DEFFILEMODE);
  if (ofd < 0) {
    std::cerr << "open: " << strerror(errno) << std::endl;
    throw std::error_code(errno, errcat);
  }
  auto rval = write(ofd, &phead, sizeof(phead));
  if (rval == -1) {
    std::cerr << "error writing header: " << strerror(errno) << std::endl;
    throw std::error_code(errno, errcat);
  }
  if (rval < (int)sizeof(phead)) {
    std::cerr << "short write writing header" << std::endl;
    close(ofd);
    throw std::error_code(EFAULT, std::generic_category());
  }
  int yes = 1;
  const socklen_t syes = sizeof(yes);
  rval = setsockopt(insock, SOL_SOCKET, SO_TIMESTAMP, &yes, syes);
  if (rval != 0) {
    std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    close(ofd);
    throw std::error_code(errno, errcat);
  }
  yes = 1;
#if defined(IP_RECVDSTADDR)
  rval = setsockopt(insock, IPPROTO_IP, IP_RECVDSTADDR, &yes, syes);
#else
  rval = setsockopt(insock, IPPROTO_IP, IP_PKTINFO, &yes, syes);
#endif
  if (rval != 0) {
    std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    close(ofd);
    throw std::error_code(errno, errcat);
  }
  auto flags = fcntl(insock, F_GETFL);
  if (fcntl(insock, F_SETFL, flags | O_NONBLOCK) < 0) {
    std::cerr << "fcntl: " << strerror(errno) << std::endl;
    close(ofd);
    throw std::error_code(errno, errcat);
  }
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = 0;
  socklen_t sin_len = sizeof(sin);
  if (bind(insock, reinterpret_cast<const sockaddr *>(&sin), sin_len) < 0) {
    std::cerr << "bind: " << strerror(errno) << std::endl;
    close(ofd);
    throw std::error_code(errno, errcat);
  }
  if (getsockname(insock, (struct sockaddr *)&sin, &sin_len) < 0) {
    std::cerr << "fcntl: " << strerror(errno) << std::endl;
    close(ofd);
    throw std::error_code(errno, errcat);
  }
  localport = sin.sin_port;

  outname = oname;
  return;
}

PCAP_Save::~PCAP_Save()
{

  close(ofd);
}

struct pkt_hdr_pcap_null {
  struct {
    struct {
      uint32_t tv_sec;
      uint32_t tv_usec;
    } ts;
    uint32_t caplen;
    uint32_t len;
  } h;
  uint32_t family;
  struct ip iphdr;
  struct udphdr udphdr;
} __attribute__((__packed__));

void
PCAP_Save::process_pkts(int insock)
{
  sockaddr_in afrom, ato;
  socklen_t fromlen, tolen;
  char recvbuf[65535];

  struct pkt_hdr_pcap_null wrkhdr;

  for (;;) {
    timeval rtime = {0, 0};
    fromlen = sizeof(afrom);
    tolen = sizeof(ato);
    auto rval = recvfromto(insock, recvbuf, sizeof(recvbuf),
      reinterpret_cast<sockaddr *>(&afrom), &fromlen,
      reinterpret_cast<sockaddr *>(&ato), &tolen, &rtime);
    if (rval < 0)
      break;
    if (fromlen != tolen || tolen != sizeof(sockaddr_in)) {
      std::cerr << "recvfromto: bogus address" << std::endl;
      throw std::error_code(EFAULT, std::generic_category());
    }
    memset(&wrkhdr, '\0', sizeof(wrkhdr));
    wrkhdr.h.len = wrkhdr.h.caplen = sizeof(wrkhdr) - sizeof(wrkhdr.h) +
     rval;
    wrkhdr.h.ts.tv_sec = rtime.tv_sec;
    wrkhdr.h.ts.tv_usec = rtime.tv_usec;
    /* Cook up IP header */
    wrkhdr.family = AF_INET;
    wrkhdr.iphdr.ip_v = 4;
    wrkhdr.iphdr.ip_hl = sizeof(struct ip) >> 2;
    wrkhdr.iphdr.ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + rval);
    wrkhdr.iphdr.ip_src = afrom.sin_addr;
    wrkhdr.iphdr.ip_dst = ato.sin_addr;
    wrkhdr.iphdr.ip_p = IPPROTO_UDP;
    wrkhdr.iphdr.ip_id = htons(ip_id++);
    wrkhdr.iphdr.ip_ttl = 127;
    wrkhdr.iphdr.ip_sum = my_in_cksum(&wrkhdr.iphdr, sizeof(struct ip));
    /* Cook up UDP header */
    wrkhdr.udphdr.uh_sport = afrom.sin_port;
    wrkhdr.udphdr.uh_dport = localport;
    auto uh_ulen = htons(sizeof(struct udphdr) + rval);
    wrkhdr.udphdr.uh_ulen = uh_ulen;
    my_ip_chksum_start();
    my_ip_chksum_update(&(wrkhdr.iphdr.ip_src), sizeof(wrkhdr.iphdr.ip_src));
    my_ip_chksum_update(&(wrkhdr.iphdr.ip_dst), sizeof(wrkhdr.iphdr.ip_dst));
    my_ip_chksum_pad_v4();
    my_ip_chksum_update(&(uh_ulen), sizeof(uh_ulen));
    my_ip_chksum_update(&(afrom.sin_port), sizeof(afrom.sin_port));
    my_ip_chksum_update(&(localport), sizeof(localport));
    my_ip_chksum_update(&(uh_ulen), sizeof(uh_ulen));
    my_ip_chksum_update_data(recvbuf, rval);
    my_ip_chksum_fin(wrkhdr.udphdr.uh_sum);
    struct iovec outv[2];
    outv[0].iov_base = &wrkhdr;
    outv[0].iov_len = sizeof(wrkhdr);
    outv[1].iov_base = recvbuf;
    outv[1].iov_len = rval;
    auto wres = writev(ofd, outv, 2);
    if (wres < (ssize_t)(outv[0].iov_len + outv[1].iov_len)) {
      if (wres < 0)
        std::cerr << "writev: " << strerror(errno) << std::endl;
      else
        std::cerr << "writev: short write" << std::endl;
      throw std::error_code(EFAULT, std::generic_category());
    }
  }

  return;
}
