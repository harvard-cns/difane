#include "prefix.h"

istream& operator >>(istream &in,prefix & p)
{
  int a, b, c, d;
  char str[IPLEN];
  in >> str;
  sscanf(str, "%d.%d.%d.%d/%u", &a, &b, &c, &d, (unsigned int *)&p.len);
  p.addr = (uint32_t)(a*(exp2(24)) + b*(exp2(16)) + c*(exp2(8)) + d);
  return in;
}

ostream& operator<< (ostream &out, const prefix &p) {
  struct in_addr tmp; 
  tmp.s_addr=ntohl(p.addr);
  out << inet_ntoa(tmp) << "/" << (int)p.len;
  return out;
}

void str2prefix(prefix &p, char * addr, int len) {
  if (strcmp(addr, "any") == 0) {
    p.addr = 0;
    p.len = 0;
    return;
  }

  int a, b, c, d;

  if (strcmp(addr, "host") == 0) {
    return;
  }

  p.len = len;

  sscanf(addr, "%d.%d.%d.%d", &a, &b, &c, &d);
  //cout << a << "." << b << "." << c << "." << d << endl;
  p.addr = (uint32_t)(a*(exp2(24)) + b*(exp2(16)) + c*(exp2(8)) + d);
  p.addr = maskbit(p.addr, p.len);  
}

void str2prefix(prefix &p, char * addr) {
  if (strcmp(addr, "any") == 0) {
    p.addr = 0;
    p.len = 0;
    return;
  }

  int a, b, c, d;

  if (strcmp(addr, "host") == 0) {
    return;
  }

  sscanf(addr, "%d.%d.%d.%d/%d", &a, &b, &c, &d, (int *)&p.len);
  //cout << a << "." << b << "." << c << "." << d << endl;
  p.addr = (uint32_t)(a*(exp2(24)) + b*(exp2(16)) + c*(exp2(8)) + d);
  p.addr = maskbit(p.addr, p.len);  
}

void str2prefix(prefix &p, char * addr, char * mask) {
  if (strcmp(addr, "any") == 0) {
    p.addr = 0;
    p.len = 0;
    return;
  }
 
  int a, b, c, d;

  if (strcmp(addr, "host") == 0) {
    sscanf(mask, "%d.%d.%d.%d", &a, &b, &c, &d);
    p.addr = (uint32_t)(a*(exp2(24)) + b*(exp2(16)) + c*(exp2(8)) + d);
    p.len = 32;
    return;
  }

  sscanf(addr, "%d.%d.%d.%d", &a, &b, &c, &d);
  //cout << a << "." << b << "." << c << "." << d << endl;
  p.addr = (uint32_t)(a*(exp2(24)) + b*(exp2(16)) + c*(exp2(8)) + d);
  sscanf(mask, "%d.%d.%d.%d", &a, &b, &c, &d);
  uint32_t mask_addr;
  mask_addr = (uint32_t)(a*(exp2(24)) + b*(exp2(16)) + c*(exp2(8)) + d);
  
  //p.addr = p.addr & mask_addr;

  p.len = 0;
  while (mask_addr > 0) {
    mask_addr = mask_addr << 1;
    p.len ++;
  }
  //p.len ++;
  
  p.addr = maskbit(p.addr, p.len);

  //cout << p.len << endl;
}

uint32_t maskbit(uint32_t addr, int len) {
  int tmplen = 32-len;
  uint64_t tmp2 = (uint64_t)0xffffffff << tmplen;
  uint64_t tmp = (uint64_t)(tmp2 & 0xffffffff);
  return addr & tmp;
}
