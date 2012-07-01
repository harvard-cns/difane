#include "interface.hh"

istream& operator >>(istream &in, interface_class & p)
{
  char str[MAX_STRING_LEN];
  char str_if_ip[IPLEN];
  char str_if_ip_mask[IPLEN];
  char str_acl_num[100];
  char str_ospf[10];

  in.getline(str, MAX_STRING_LEN);
  if (strcmp(str, "") == 0) {
    p.router_id = -1;
    return in;
  }

  //cout << str << endl;

  p.type = INTERFACE_EXTERNAL;

  char * pch, *prev;
  //network
  pch = strchr(str, '|');
  
  char router_name[100];
  prev = pch+1;
  pch = strchr(pch+1, '|');
  strncpy(router_name, prev, pch-prev);
  router_name[pch-prev] = 0;
  //cout << p.router_name <<endl;
  if (routermap.find(router_name) == routermap.end()) {
    routermap[router_name] = nrouter;
    nrouter++;
  } 
  p.router_id = routermap[router_name];


  //card
  pch = strchr(pch+1, '|');
  //interface_date
  pch = strchr(pch+1, '|');
  //interface_type
  pch = strchr(pch+1, '|');
  
  //interface_ip/mask
  prev = pch+1;
  pch = strchr(pch+1, '|');
  strncpy(str_if_ip, prev, pch-prev);
  str_if_ip[pch-prev] = 0;
  if (strcmp(str_if_ip, "") == 0 || strcmp(str_if_ip, "none") == 0) {
    p.router_id = -1; return in;
  }
  prev = pch+1;
  strcpy(str_if_ip_mask, "255.255.255.255");
  pch = strchr(pch+1, '|');
  if (pch != NULL) {
    strncpy(str_if_ip_mask, prev, pch-prev);
    str_if_ip_mask[pch-prev] = 0;
  }
  str2prefix(p.interface, str_if_ip, str_if_ip_mask);
  /*if (strcmp(router_name, "abyny32c3") == 0 && strcmp(str_if_ip, "12.123.219.73")  == 0) {
    cout << str_if_ip_mask << " " << p.interface << endl;
    str2prefix(p.interface, str_if_ip, str_if_ip_mask);
    exit(0);
    }*/
  //description
  pch = strchr(pch+1, '|');
  //shutdown
  pch = strchr(pch+1, '|');
  //encapsulation
  pch = strchr(pch+1, '|');

  //ospf weight
  prev = pch+1; 
  pch = strchr(pch+1, '|');
  strncpy(str_ospf, prev, pch-prev);
  str_ospf[pch-prev] = 0;
  p.ospf_weight = atoi(str_ospf);

  p.in_acl = p.out_acl = -1;

  //acl_num in/out
  prev = pch+1; 
  pch = strchr(pch+1, '|');
  strncpy(str_acl_num, prev, pch-prev);
  str_acl_num[pch-prev] = 0;
  if (strcmp(str_acl_num, "") != 0) {
    p.in_acl = atoi(str_acl_num);
  } else p.in_acl = -1;
  
  prev = pch+1; 
  pch = strchr(pch+1, '|');
  if (!pch) {
    strcpy(str_acl_num, prev);
  } else {
    strncpy(str_acl_num, prev, pch-prev);
    str_acl_num[pch-prev] = 0;
  }
  if (strcmp(str_acl_num, "") != 0) {
    p.out_acl = atoi(str_acl_num);
  } else p.out_acl = -1;

  return in;
}

ostream& operator<< (ostream &out, const interface_class &p) {
  out << " interface " << p.interface 
      << " router_id " << p.router_id 
      << " ospf_weight " << p.ospf_weight 
      << " in_acl " << p.in_acl 
      << " out_acl " << p.out_acl;
  return out;
}
