#ifndef CUBE_HH
#define CUBE_HH

#include "acl.hh"

class hypercube {
public:
  range_class router, sport, dport, src, dst, protocol;

  hypercube() {
  }

  hypercube(range_class prouter, range_class psport, range_class pdport, range_class psrc, range_class pdst, range_class pprotocol) {
    router = prouter;
    sport = psport;
    dport = pdport;
    src = psrc;
    dst = pdst;
    protocol = pprotocol;
  }

  hypercube & operator=(const hypercube& p) {
    router = p.router;
    sport = p.sport;
    dport = p.dport;
    src = p.src;
    dst = p.dst;
    protocol = p.protocol;
    return *this;
  }

  void set(int index, uint32_t start, uint32_t end) {
    switch (index) {
    case 0: 
      router.first = start;
      router.last = end;
      break;
    case 1: 
      src.first = start;
      src.last = end;
      break;
    case 2: 
      dst.first = start;
      dst.last = end;
      break;
    case 3: 
      sport.first = start;
      sport.last = end;
      break;
    case 4: 
      dport.first = start;
      dport.last = end;
      break;
    case 5: 
      protocol.first = start;
      protocol.last = end;
      break;
    }
  }

  void get(int index, uint32_t & start, uint32_t &end) {
    switch (index) {
    case 0: 
      start = router.first;
      end = router.last;
      break;
    case 1: 
      start = src.first;
      end = src.last;
      break;
    case 2: 
      start = dst.first;
      end = dst.last;
      break;
    case 3: 
      start = sport.first;
      end = sport.last;
      break;
    case 4: 
      start = dport.first;
      end = dport.last;
      break;
    case 5: 
      start = protocol.first;
      end = protocol.last;
      break;
    }
  }

  friend ostream& operator<< (ostream &, const hypercube &);

};

int partition(hypercube cube, int);


#endif
