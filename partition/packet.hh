#ifndef PACKET_HH
#define PACKET_HH

long long start_pkt_time = -1;

class packet_class {
 public:
  prefix src, dst;
  uint32_t protocol;
  int time;
  
  void getpkt(char * str) {
    char strtmp[255];
    char * pch, *prev;
    char mask[100];
    strcpy(mask, "255.255.255.255");
    prefix p;

    long long tmptime;
    pch = strchr(str, '|');
    strncpy(strtmp, str, pch - str);
    tmptime = atoi(strtmp);
    if (start_pkt_time == -1) {
      time = 0;
      start_pkt_time = tmptime;
    } else {
      time = tmptime - start_pkt_time;
    }

    for (int i = 0; i < 9; i ++) 
      pch = strchr(pch+1, '|');

    prev = pch+1;
    pch = strchr(pch+1, '|');
    strncpy(strtmp, prev, pch-prev);
    strtmp[pch-prev] = 0;
    protocol = atoi(strtmp);

    prev = pch+1;
    pch = strchr(pch+1, '|');
    strncpy(strtmp, prev, pch-prev);
    strtmp[pch-prev] = 0;
    str2prefix(src, strtmp, mask);

    prev = pch+1;
    pch = strchr(pch+1, '|');
    if (pch) {
      strncpy(strtmp, prev, pch-prev);
      strtmp[pch-prev] = 0;
    } else {
      strcpy(strtmp, prev);
    }
    str2prefix(dst, strtmp, mask);
  }

};

class cache_entry {
public:
  prefix src, dst;
  int time;

  bool match(packet_class pkt) {
    if (src.contains(pkt.src) && dst.contains(pkt.dst)) {
      return true;
    } else {
      return false;
    }
  }
};

#endif
