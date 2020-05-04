// © 2020 Erik Rigtorp <erik@rigtorp.se>
// (c) 2019 Maksym Sobolyev <sobomax@sippysoft.com>
// SPDX-License-Identifier: MIT

#include <cstring>
#include <iostream>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <math.h>
#include <unistd.h>

#include "pcap_save.h"
#include "timespecops.h"

int main(int argc, char *argv[]) {

  int ifindex = 0;
  int loopback = 0;
  double speed = 1;
  timespec speed_ts;
  int interval = -1;
  int repeat = 1;
  int ttl = -1;
  int broadcast = 0;
  int nmax = -1;
  timespec interval_ts = {0, 0};
  const char *outfile = nullptr;
  PCAP_Save *saver = nullptr;

  int opt;
  while ((opt = getopt(argc, argv, "i:bls:c:r:t:o:n:")) != -1) {
    switch (opt) {
    case 'i':
      ifindex = if_nametoindex(optarg);
      if (ifindex == 0) {
        std::cerr << "if_nametoindex: " << strerror(errno) << std::endl;
        return 1;
      }
      break;
    case 'l':
      loopback = 1;
      break;
    case 's':
      speed = std::stod(optarg);
      if (speed < 0) {
        std::cerr << "speed must be positive" << std::endl;
      }
      if (speed != 1.0) {
        double2timespec(speed, &speed_ts);
      }
      break;
    case 'c':
      interval = std::stoi(optarg);
      if (interval < 0) {
        std::cerr << "interval must be non-negative integer" << std::endl;
        return 1;
      }
      interval_ts.tv_sec = interval / 1000;
      interval_ts.tv_nsec = (interval - (interval_ts.tv_sec * 1000)) * 1000000;
      break;
    case 'r':
      repeat = std::stoi(optarg);
      if (repeat != -1 && repeat <= 0) {
        std::cerr << "repeat must be positive integer or -1" << std::endl;
        return 1;
      }
      break;
    case 't':
      ttl = std::stoi(optarg);
      if (ttl < 0) {
        std::cerr << "ttl must be non-negative integer" << std::endl;
        return 1;
      }
      break;
    case 'b':
      broadcast = 1;
      break;
    case 'o':
      outfile = optarg;
      break;
    case 'n':
      nmax = std::stoi(optarg);
      if (nmax <= 0) {
        std::cerr << "npkts must be positive integer" << std::endl;
        return 1;
      }
      break;
    default:
      goto usage;
    }
  }
  if (optind >= argc) {
  usage:
    std::cerr
        << "udpreplay 1.0.0 © 2020 Erik Rigtorp <erik@rigtorp.se> "
           "https://github.com/rigtorp/udpreplay\n"
           "usage: udpreplay [-i iface] [-l] [-s speed] [-c millisec] [-r "
           "repeat] [-t ttl] [-o outfile] [-n npkts] "
           "pcap\n"
           "\n"
           "  -i iface    interface to send packets through\n"
           "  -l          enable loopback\n"
           "  -c millisec constant milliseconds between packets\n"
           "  -r repeat   number of times to loop data (-1 for infinite loop)\n"
           "  -s speed    replay speed relative to pcap timestamps\n"
           "  -t ttl      packet ttl\n"
           "  -o outfile  save incoming packets into the PCAP file\n"
           "  -n npkts    replay max of npkts packets\n"
           "  -b          enable broadcast (SO_BROADCAST)"
        << std::endl;
    return 1;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    std::cerr << "socket: " << strerror(errno) << std::endl;
    return 1;
  }

  if (ifindex != 0) {
    ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_ifindex = ifindex;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) ==
        -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (loopback != 0) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback,
                   sizeof(loopback)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (broadcast != 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast,
                   sizeof(broadcast)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (ttl != -1) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  timespec last = {0, 0};
  const timespec *sleepuntp = nullptr;

  if (outfile != nullptr) {
    try {
      saver = new PCAP_Save(outfile, fd);
    } catch (std::error_code& e) {
      return 1;
    }
  }

  for (int i = 0; repeat == -1 || i < repeat; i++) {
    char errbuf[PCAP_ERRBUF_SIZE];
    auto *handle = pcap_open_offline_with_tstamp_precision(argv[optind],
     PCAP_TSTAMP_PRECISION_NANO, errbuf);

    if (handle == nullptr) {
      std::cerr << "pcap_open: " << errbuf << std::endl;
      goto fatalerr;
    }

    pcap_pkthdr header;
    const u_char *p;
    timespec pcap_last = {0, 0};
    const timespec *plastp  = nullptr;
    while ((p = pcap_next(handle, &header))) {
      if (header.len != header.caplen) {
        continue;
      }
      auto eth = reinterpret_cast<const ether_header *>(p);

      // jump over and ignore vlan tags
      while (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
        p += 4;
        eth = reinterpret_cast<const ether_header *>(p);
      }
      if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        continue;
      }
      auto ip = reinterpret_cast<const struct ip *>(p + sizeof(ether_header));
      if (ip->ip_v != 4) {
        continue;
      }
      if (ip->ip_p != IPPROTO_UDP) {
        continue;
      }
      auto udp = reinterpret_cast<const udphdr *>(p + sizeof(ether_header) +
                                                  ip->ip_hl * 4);

      /*
       * There is no mistake below: when PCAP_TSTAMP_PRECISION_NANO is
       * set, tv_usec field in the header represents *NANO*seconds, not
       * micro.
       */
      timespec header_ts = {header.ts.tv_sec, header.ts.tv_usec};
      bool skipdelay = false;
      if (sleepuntp == nullptr) {
        if (clock_gettime(CLOCK_MONOTONIC, &last) == -1) {
          std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
          pcap_close(handle);
          goto fatalerr;
        }
        sleepuntp = &last;
        skipdelay = true;
      }
      if (plastp == nullptr) {
        pcap_last = header_ts;
        plastp = &pcap_last;
        /*
         * The interval == -1 clause below covers fixed interval case when
         * we've repen playback.
         */
        if (!skipdelay && interval == -1)
          skipdelay = true;
      }
      if (skipdelay || interval == 0)
        goto nodelay;

      if (interval == -1) {
        interval_ts = header_ts;
        timespecsub(&interval_ts, plastp);
        if (speed != 1.0) {
          timespecmul(&interval_ts, &speed_ts, &interval_ts);
        }
        pcap_last = header_ts;
      }
      timespecadd(&last, &interval_ts);
      clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, sleepuntp, NULL);

nodelay:
      ssize_t len = ntohs(udp->uh_ulen) - 8;
      const u_char *d =
          &p[sizeof(ether_header) + ip->ip_hl * 4 + sizeof(udphdr)];

      sockaddr_in addr;
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_port = udp->uh_dport;
      addr.sin_addr = {ip->ip_dst};
      auto n = sendto(fd, d, len, 0, reinterpret_cast<sockaddr *>(&addr),
                      sizeof(addr));
      if (n != len) {
        if (n < 0)
          std::cerr << "sendto: " << strerror(errno) << std::endl;
        else
          std::cerr << "sendto: short write" << std::endl;
        pcap_close(handle);
        goto fatalerr;
      }
      if (nmax > 0) {
        nmax -= 1;
        if (nmax == 0) {
            pcap_close(handle);
            goto done;
        }
      }
      if (saver != nullptr) {
        try {
          saver->process_pkts(fd);
        } catch (std::error_code& e) {
          pcap_close(handle);
          goto fatalerr;
        }
      }
    }

    pcap_close(handle);
  }

done:
  if (saver != nullptr) {
    delete saver;
  }
  return 0;

fatalerr:
  if (saver != nullptr) {
    delete saver;
  }
  return 1;
}
