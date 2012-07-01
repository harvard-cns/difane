#ifndef PREFIX_H
#define PREFIX_H

#include "util.h"

uint32_t maskbit(uint32_t addr, int len);

class prefix {
 public:
  uint32_t addr;
  uint8_t len;
  prefix() {
    addr = 0;
    len = 0;
  }
    prefix(uint32_t a, char l): addr(a), len(l) { }
    prefix(const prefix& p) {
      addr=p.addr;
      len=p.len;
    }
    void set(uint32_t a, char l) {
      addr=a; len=l;
    }
    prefix& operator=(const prefix& p) {
      addr=p.addr;
      len=p.len;
      return *this;
    }
    bool operator==(const prefix& p) const {
      if (addr ==p.addr  && len==p.len) {
        return true;
      }
      else {
        return false;
      }
    }
    bool operator!=(const prefix& p) const {
      if (addr ==p.addr  && len==p.len) {
        return false;
      }
      else {
        return true;
      }
    }
    bool operator<(const prefix& p) const {
      if (len<p.len) {
        return true;
      }
      else if (len==p.len) {
        return (addr <p.addr);
      }
      else {
        return false;
      }
    }

    bool contains(const prefix& p) const {
      if (len > p.len) return false;
      if (len == p.len && addr != p.addr) return false;
      uint32_t paddr = maskbit(p.addr, len);
      if (addr == paddr) return true; 
      return false;
    }

    void getrange(uint32_t & first, uint32_t & last) {
      first = addr;
      double tmp = exp2(32-len);
      last = (uint32_t)(addr - 1 + tmp);
      if (last < first) {
        perror("getrange");
        last = first;
      }
        //cout << "error" << endl;
      //if (len == 32) last ++;
      //cout << " len " << (int)len << " tmp " << tmp << endl;
    }

    friend ostream& operator<< (ostream &, const prefix &);
    friend istream& operator>> (istream &, prefix &);
};

void str2prefix(prefix &p, char * addr, char * mask);
void str2prefix(prefix &p, char * addr, int len);
void str2prefix(prefix &p, char * addr);


#endif
