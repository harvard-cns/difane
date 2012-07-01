#include "link.hh"

istream& operator >>(istream &in, link_class & p)
{
  char str[MAX_STRING_LEN];
  char str_if_ip[IPLEN];
  char str_if_ip_mask[IPLEN];
  char router_name[100];
  int iplen;

  in.getline(str, MAX_STRING_LEN);
  if (strcmp(str, "") == 0) {
    p.router1 = -1;
    return in;
  }

  //cout << str << endl;

  char * pch, *prev;
  //network
  pch = strchr(str, '|');
  if (pch == NULL) {
    p.router1 = -1;
    return in;
  }
  
  //interface_ip/mask
  prev = pch+1;
  pch = strchr(pch+1, '|');
  strncpy(str_if_ip, prev, pch-prev);
  str_if_ip[pch-prev] = 0;
  //strcpy(str_if_ip_mask, "255.255.255.255");
  prev = pch+1;
  pch = strchr(pch+1, '|');
  if (pch != NULL) {
    strncpy(str_if_ip_mask, prev, pch-prev);
    str_if_ip_mask[pch-prev] = 0;
  }
  iplen = atoi(str_if_ip_mask);
  str2prefix(p.link, str_if_ip, iplen);

  //router_date
  pch = strchr(pch+1, '|');

  //router1
  prev = pch+1;
  pch = strchr(pch+1, '|');
  strncpy(router_name, prev, pch-prev);
  router_name[pch-prev] = 0;
  //cout << p.router_name <<endl;
  if (routermap.find(router_name) == routermap.end()) {
    routermap[router_name] = nrouter;
    nrouter++;
  } 
  p.router1 = routermap[router_name];

  //card1
  pch = strchr(pch+1, '|');

  //router2
  prev = pch+1;
  pch = strchr(pch+1, '|');
  strncpy(router_name, prev, pch-prev);
  router_name[pch-prev] = 0;
  //cout << p.router_name <<endl;
  if (routermap.find(router_name) == routermap.end()) {
    routermap[router_name] = nrouter;
    nrouter++;
  } 
  p.router2 = routermap[router_name];

  if (p.router1 == 0 && p.router2 == 668) 
    cout << "hello " << endl;

  return in;
}
