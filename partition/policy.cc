#include "policy.hh"

int convert_port(char * str) {
  if (strcmp(str, "snmp") == 0) return 161;
  if (strcmp(str, "snmptrap") == 0) return 162;
  if (strcmp(str, "tacacs") == 0) return 49;
  if (strcmp(str, "ntp") == 0) return 123;
  if (strcmp(str, "tftp") == 0) return 69;
  if (strcmp(str, "echo") == 0) return 7;
  if (strcmp(str, "telnet") == 0) return 23;
  if (strcmp(str, "bgp") == 0) return 179;
  if (strcmp(str, "bootpc") == 0) return 68;
  if (strcmp(str, "bootps") == 0) return 67;
  if (strcmp(str, "ftp") == 0) return 21;
  if (strcmp(str, "domain") == 0) return 53;
  if (strcmp(str, "pop3") == 0) return 110;
  if (strcmp(str, "www") == 0) return 80;
  if (strcmp(str, "smtp") == 0) return 25;
  if (strcmp(str, "chargen") == 0) return 19;
  if (strcmp(str, "pim-auto-rp") == 0) return 496;
  if (strcmp(str, "isakmp") == 0) return 500;
  if (strcmp(str, "biff") == 0) return 512;
  if (strcmp(str, "netbios-ns") == 0) return 137;
  if (strcmp(str, "netbios-dgm") == 0) return 138;
  if (strcmp(str, "netbios-ss") == 0) return 139;
  if (strcmp(str, "exec") == 0) return 512;

  //unsure
  if (strcmp(str, "lLth9012b03GJ") == 0) return 1;

 
  int port = atoi(str);
  char strtmp[255];
  sprintf(strtmp, "%d", port);
  if (strcmp(str, strtmp) != 0) {
    cout << str << endl;
  }
  return port;
}

istream& operator >>(istream &in, policy_class & p)
{
  char str[MAX_STRING_LEN];
  char str_action[10];
  char str_protocol[10];
  char str_src[IPLEN];
  char str_src_mask[IPLEN];
  char str_dst[IPLEN];
  char str_dst_mask[IPLEN];
  char str_acl_num[100];
  char str_entry_index[100];
  char str_port[100];
  char str_tmp[100];
  char str_network[100];

  in.getline(str, MAX_STRING_LEN);
  //cout << str << endl;
   
  char * pch, *prev;
  //network
  pch = strchr(str, '|');
  if (pch == NULL) {
    p.router_id = -1;
    return in;
  } else {
    strncpy(str_network, str, pch - str);
  }
  
  char router_name[30];
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

  if (file_format == FORMAT_LIGHTSPEED) {
    //acl_date  
    pch = strchr(pch+1, '|');
  }

  //acl_num
  prev = pch+1; 
  pch = strchr(pch+1, '|');
  strncpy(str_acl_num, prev, pch-prev);
  str_acl_num[pch-prev] = 0;
  if (strcmp(str_acl_num, "rate-limit") == 0) {
    p.action = ACTION_RATE_LIMIT;
    return in;
  }
  if (strcmp(str_acl_num, "INBOUND-SPEED-TRAP") == 0) {
    p.action = ACTION_RATE_LIMIT;
    return in;
  }
  if (strcmp(str_acl_num, "ldp-filter") == 0) {
    p.action = ACTION_RATE_LIMIT;
    return in;
  }
  if (strstr(str_acl_num, "US_msdp_group") != NULL) {
    p.action = ACTION_RATE_LIMIT;
    return in;
  }
  p.acl_num = atoi(str_acl_num);

  //entry_index
  prev = pch+1; 
  pch = strchr(pch+1, '|');
  strncpy(str_entry_index, prev, pch-prev);
  str_entry_index[pch-prev] = 0;
  p.entry_index = atoi(str_entry_index);

  if (file_format != FORMAT_LIGHTSPEED) {
    //acl_date  
    pch = strchr(pch+1, '|');
  }

  //Sequence number
  if (file_format == FORMAT_XR) {
    pch = strchr(pch+1, '|'); 
  }

  prev = pch+1;
  pch = strchr(pch+1, '|');
  strncpy(str_action, prev, pch-prev);
  str_action[pch-prev] = 0;
  //cout << str_action << endl;
  if (strcmp(str_action, "permit") == 0) 
    p.action = ACTION_ACCEPT;
  else if (strstr(str_action, "permit") != 0) {
    p.action = ACTION_ACCEPT;
  }
  else if (strcmp(str_action, "deny") == 0) 
    p.action = ACTION_DENY;
  else if (strcmp(str_action, "read-only") == 0)
    p.action = ACTION_READONLY;
  else if (strcmp(str_action, "") == 0) {
    p.action = ACTION_RATE_LIMIT;
    return in;
  }
  else {
    cout << str << endl;
    cout << str_action << endl;
    perror("action");
  }

  p.protocol = 255;
  if (file_format == FORMAT_EXT || file_format == FORMAT_LIGHTSPEED || file_format == FORMAT_XR) {
    prev = pch+1;
    pch = strchr(pch+1, '|');
    strncpy(str_protocol, prev, pch-prev);
    str_protocol[pch-prev] = 0;
    int port;
    //cout << str_protocol << endl;
    if (strcmp(str_protocol, "ip") == 0 || strcmp(str_protocol, "any") == 0 || strcmp(str_protocol, "*") == 0) 
      p.protocol = PROTO_IP;
    else if (strcmp(str_protocol, "udp") == 0) 
      p.protocol = PROTO_UDP;
    else if (strcmp(str_protocol, "tcp") == 0) 
      p.protocol = PROTO_TCP;
    else if (strcmp(str_protocol, "icmp") == 0) 
      p.protocol = PROTO_ICMP;
    else if (strcmp(str_protocol, "ospf") == 0) 
      p.protocol = PROTO_OSPF;
    else if (strcmp(str_protocol, "gre") == 0) 
      p.protocol = PROTO_GRE;
    else if (strcmp(str_protocol, "igmp") == 0) 
      p.protocol = PROTO_IGMP;
    else if (strcmp(str_protocol, "pim") == 0) 
      p.protocol = PROTO_PIM;
    else if (strcmp(str_protocol, "ipinip") == 0) 
      p.protocol = PROTO_IPINIP;
    else if (strcmp(str_protocol, "esp") == 0) 
      p.protocol = PROTO_ESP;
    else if (strcmp(str_protocol, "arp") == 0) 
      p.protocol = PROTO_ARP;
    else if (strcmp(str_protocol, "eigrp") == 0) 
      p.protocol = PROTO_EIGRP;
    else if (strcmp(str_protocol, "nos") == 0) 
      p.protocol = PROTO_NOS;
    else if (strcmp(str_protocol, "pop") == 0) 
      p.protocol = PROTO_POP;
    else if (strcmp(str_protocol, "pcp") == 0) 
      p.protocol = PROTO_PCP;
    else if (strcmp(str_protocol, "ahp") == 0) 
      p.protocol = PROTO_AHP;
    else if (strcmp(str_protocol, "ipv4") == 0) 
      p.protocol = PROTO_IPV4;
    else if (strcmp(str_protocol, "vrrp") == 0) 
      p.protocol = PROTO_VRRP;
    else if (strcmp(str_protocol, "rsvp") == 0) 
      p.protocol = PROTO_RSVP;
    else {
      port = atoi(str_protocol);
      if (port > 0) {
        p.protocol = PROTO_BASE + port;
      } else {
        cout << str << endl;
        cout << str_action << endl;
        perror("protocol");
      }
    }
  }

  p.sport.first = 0;
  p.sport.last = MAX_PORT;
  p.dport.first = 0;
  p.dport.last = MAX_PORT;

  if (file_format == FORMAT_LIGHTSPEED) {
    prev = pch+1;
    pch = strchr(pch+1, '|');
    if (!pch) perror("src");
    strncpy(str_tmp, prev, pch-prev);
    str_tmp[pch-prev] = 0;
    str2prefix(p.src, str_tmp);
    //cout << p.src << endl;

    prev = pch+1;
    pch = strchr(pch+1, '|');
    if (pch) {
      strncpy(str_port, prev, pch-prev);
      str_port[pch-prev] = 0;
    }
    if (strcmp(str_port, "any") != 0) {
      if (strstr(str_port, "range") != NULL) {
        sscanf(str_port, "range %d %d", &p.sport.first, &p.sport.last);
      } else {
        p.sport.first = atoi(str_port);
        p.sport.last = p.sport.first;
      }
    }

    prev = pch+1;
    pch = strchr(pch+1, '|');
    if (!pch) perror("dst");
    strncpy(str_tmp, prev, pch-prev);
    str_tmp[pch-prev] = 0;
    str2prefix(p.dst, str_tmp);
    //cout << p.dst << endl;

    prev = pch+1;
    pch = strchr(pch+1, '|');
    if (pch) {
      strncpy(str_port, prev, pch-prev);
      str_port[pch-prev] = 0;
    }
    if (strcmp(str_port, "any") != 0) {
      if (strstr(str_port, "range") != NULL) {
        sscanf(str_port, "range %d %d", &p.dport.first, &p.dport.last);
      } else {
        p.dport.first = atoi(str_port);
        p.dport.last = p.dport.first;
      }
    }

    return in;
  }


  prev = pch+1;
  pch = strchr(pch+1, '|');
  strncpy(str_src, prev, pch-prev);
  str_src[pch-prev] = 0;
  prev = pch+1;
  pch = strchr(pch+1, '|');
  if (pch) {
    strncpy(str_tmp, prev, pch-prev);
    str_tmp[pch-prev] = 0;
  } else {
    strcpy(str_tmp, prev);
  }
  if (strcmp(str_tmp, "gt") != 0 && strcmp(str_tmp, "eq") != 0 && strcmp(str_tmp, "range") != 0 && strcmp(str_tmp, "") != 0) {
    strcpy(str_dst, "");
    strcpy(str_src_mask, str_tmp);
  } else {
    strcpy(str_dst, str_tmp);
    strcpy(str_src_mask, "255.255.255.255");
  }
  str2prefix(p.src, str_src, str_src_mask);
  //cout << p.src << endl;


  if (file_format == FORMAT_EXT || file_format == FORMAT_XR) {
    if (strcmp(str_dst, "") == 0) {
      prev = pch+1;
      pch = strchr(pch+1, '|');
      if (pch) {
        strncpy(str_dst, prev, pch-prev);
        str_dst[pch-prev] = 0;
      }
    }

    //for EXT
    if (strcmp(str_dst, "gt") == 0 || strcmp(str_dst, "eq") == 0 || strcmp(str_dst, "range") == 0) {
      prev = pch+1;
      pch = strchr(pch+1, '|');
      strncpy(str_port, prev, pch-prev);
      str_port[pch-prev] = 0;
      
      if (strcmp(str_dst, "gt") == 0) {
        p.sport.first = convert_port(str_port) + 1;
        p.sport.last = MAX_PORT;
      }
      
      if (strcmp(str_dst, "eq") == 0) {
        if (strcmp(str_port, "ftp-data") != 0) {
          p.sport.first = convert_port(str_port);
          p.sport.last = p.sport.first;
        }
      }

      if (strcmp(str_dst, "range") == 0) {
        if (strcmp(str_port, "bootps") !=0) {
          p.sport.first = convert_port(str_port);
          prev = pch+1;
          pch = strchr(pch+1, '|');
          strncpy(str_port, prev, pch-prev);
          str_port[pch-prev] = 0;
          p.sport.last = convert_port(str_port);
        } else {
          pch = strchr(pch+1, '|');
        }
      }
    
      prev = pch+1;
      pch = strchr(pch+1, '|');
      if (!pch) strcpy(str_dst, ""); 
      else {
        strncpy(str_dst, prev, pch-prev);
        str_dst[pch-prev] = 0;
      }      
    }
    
    if (strcmp(str_dst, "") == 0) {
      strcpy(str_dst, "any");
      strcpy(str_dst_mask, "255.255.255.255");
      str2prefix(p.dst, str_dst, str_dst_mask);
      return in;
    }

    prev = pch+1;
    pch = strchr(pch+1, '|');
    if (pch) {
      strncpy(str_tmp, prev, pch-prev);
      str_tmp[pch-prev] = 0;
    } else strcpy(str_tmp, prev);
    if (strcmp(str_tmp, "gt") != 0 && strcmp(str_tmp, "eq") != 0 && strcmp(str_tmp, "range") != 0 && strcmp(str_tmp, "") != 0
        && strcmp(str_tmp, "established") != 0) {
      strcpy(str_port, "");
      strcpy(str_dst_mask, str_tmp);
    } else {
      strcpy(str_dst_mask, "255.255.255.255");
      strcpy(str_port, str_tmp);
    }
    
    str2prefix(p.dst, str_dst, str_dst_mask);
    //cout << p.dst << endl;

    if (strcmp(str_port, "") == 0 && pch) {
      prev = pch+1;
      pch = strchr(pch+1, '|');
      if (!pch) return in;
      strncpy(str_dst, prev, pch-prev);
      str_dst[pch-prev] = 0;
    }
    strcpy(str_dst, str_port);
    if (strcmp(str_dst, "gt") == 0 || strcmp(str_dst, "eq") == 0 || strcmp(str_dst, "range") == 0) {
      prev = pch+1;
      pch = strchr(pch+1, '|');
      if (pch) {
        strncpy(str_port, prev, pch-prev);
        str_port[pch-prev] = 0;
      } else {
        strcpy(str_port, prev);
      }

      if (strcmp(str_dst, "gt") == 0) {
        p.dport.first = convert_port(str_port) + 1;
        p.dport.last = MAX_PORT;
      }
      
      if (strcmp(str_dst, "eq") == 0 && strcmp(str_port, "tacacs") !=0 && strcmp(str_port, "ftp-data")!= 0) {
        p.dport.first = convert_port(str_port);
        p.dport.last = p.dport.first;
      }

      if (strcmp(str_dst, "range") == 0) {
        p.dport.first = convert_port(str_port);
        prev = pch+1;
        pch = strchr(pch+1, '|');
        if (pch) {
          strncpy(str_port, prev, pch-prev);
          str_port[pch-prev] = 0;
        } else {
          strcpy(str_port, prev);
        }
        p.dport.last = convert_port(str_port);
      }
    
    }


  }

  // cout << p << endl;

  return in;
}

ostream& operator<< (ostream &out, const policy_class &p) {
  out << " id " << p.router_id 
      << " priority " << p.entry_index 
      << " action " << (int)p.action 
      << " protocol " << p.protocol 
      << " src " << p.src 
      << " dst " << p.dst;
  return out;
}
