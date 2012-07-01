#include "readfile.hh"
#include "policy.hh"
#include "interface.hh"

class range_class;
extern int network;

extern set<uint32_t> proto_count, sp_count, dp_count, sip_count, dip_count;

void read_interface(char * filename) {
  ifstream in(filename);
  interface_class interface;
  while (in >> interface) {
    if (interface.router_id < 0) continue;
    //if (interface.router_id == 668) 
    //  cout << get_router(interface.router_id) << interface << endl;
    interface_set[interface.router_id].push_back(interface);
  }
}

void read_network(char * filename) {
  ifstream in(filename);
  link_class link;
  acl_link_list = new acl_link_class[nrouter*nrouter];

  while ( in >> link) {
    if (link.router1  < 0) continue;
    vector<interface_class>::iterator si, si2;
    //cout << link.link << endl;
    //cout << interface_set[link.router1].size() << endl;
    for (si = interface_set[link.router1].begin(); si != interface_set[link.router1].end(); si ++) {
      //cout << si->interface << " " << link.router1 << " " << get_router(link.router1) << endl;
      if (link.link.contains(si->interface)) {
        break;
      }
    }
    for (si2 = interface_set[link.router2].begin(); si2 != interface_set[link.router2].end(); si2 ++) {
      if (link.link.contains(si2->interface)) {
        break;
      }
    }
    if (si == interface_set[link.router1].end()) {
      perror("read_network1");
      cout << get_router(link.router1) << " " << get_router(link.router2) << " " <<  link.link << endl; 
      exit(0);
    }
    if (si2 == interface_set[link.router2].end()) {
      perror("read_network2");
      exit(0);
    }

    if (si->ospf_weight < 0) {
      cout << get_router(link.router1) << " " << si->interface << endl;
      perror("read_network1: ospf_weight");
      //exit(0);
    }

    if (si2->ospf_weight < 0) {
      cout << get_router(link.router2) << " " << si2->interface << endl;
      perror("read_network2: ospf_weight");
      //exit(0);
    }
    
    //if (si->ospf_weight > 0 && si2->ospf_weight >0) {
    link_list[nlink].from = link.router1;
    link_list[nlink].to = link.router2;
    link_list[nlink].weight = si->ospf_weight;
    acl_link_list[link.router1 * nrouter+link.router2].acl1 = si->out_acl;
    acl_link_list[link.router1*nrouter+link.router2].acl2 = si2->in_acl;
    nlink++;
    link_list[nlink].from = link.router2;
    link_list[nlink].to = link.router1;
    link_list[nlink].weight = si2->ospf_weight;
    acl_link_list[link.router2 * nrouter+link.router1].acl1 = si2->out_acl;
    acl_link_list[link.router2*nrouter+link.router1].acl2 = si->in_acl;    
    nlink ++;

    si->type = INTERFACE_INTERNAL;
    si2->type = INTERFACE_INTERNAL;
    //}

  }
}

extern long totalrules;
void read_file(char * filename) {
  ifstream in(filename);
  while (in >> policy_list[nrule]) {
    if (policy_list[nrule].router_id < 0) 
      continue;
    if (policy_list[nrule].action == ACTION_RATE_LIMIT || policy_list[nrule].action == ACTION_READONLY) {
      continue;
    }
    if (nrule == totalrules) break;
    if (nrule % 1000000 == 0 && nrule > 0) {
      cout << nrule << endl;
      //break;
      //#ifdef DEBUG 
      //if (network == NETWORK_CBB) break;
      //#endif
    }

    /*if (policy_list[nrule].router_id == 0) {
      cout << policy_list[nrule] << endl;
      }*/

    /*if (policy_list[nrule].router_id == 1380) {
      cout << policy_list[nrule].router_id << endl;
      }*/

    proto_count.insert(policy_list[nrule].protocol);
    sp_count.insert(policy_list[nrule].sport.first);
    sp_count.insert(policy_list[nrule].sport.last);
    dp_count.insert(policy_list[nrule].dport.first);
    dp_count.insert(policy_list[nrule].dport.last);
    range_class r;
    policy_list[nrule].src.getrange(r.first, r.last);
    sip_count.insert(r.first);
    sip_count.insert(r.last);
    policy_list[nrule].dst.getrange(r.first, r.last);
    dip_count.insert(r.first);
    dip_count.insert(r.last);

    policy_index_class pindex(nrule, policy_list[nrule].entry_index);
    //router_rules[policy_list[nrule].router_id].push_back(pindex);
    router_interface_class ri(policy_list[nrule].router_id, policy_list[nrule].acl_num);
    rule_group[ri].push_back(pindex);
  
    //measurement
    acl_per_router[policy_list[nrule].router_id].insert(policy_list[nrule].acl_num);

    nrule ++;
  }
}


void read_file_campus(char * filename, int rid) {
  ifstream in(filename);
  
  void * rt = in.getline(str, MAX_STRING_LEN);
  
  char * pch, *prev;
  char str_action[100];
  char str_protocol[100];
  char str_src[100];
  char str_dst[100];
  //char str_src_port[100];
  char str_src_mask[100];
  char str_dst_port[100];
  char str_dst_mask[100];

  int tmpindex;
  int acl_num = 0;

  while (rt) {
    if (!strstr(str, "ip access-list")) {
      rt = in.getline(str, MAX_STRING_LEN);
      continue;
    }
    tmpindex = 0; 
    rt = in.getline(str, MAX_STRING_LEN);
    while (rt  && !strstr(str, "ip access-list")) {
      //cout << str << endl;
      
      policy_class p;
      pch = prev = NULL;
      pch = strchr(str, ' ');
      if (!pch) break;
      prev = pch + 1;
      pch = strchr(pch+1, ' ');
      strncpy(str_action, prev, pch - prev);
      str_action[pch-prev] = 0;
      if (strcmp(str_action, "permit") == 0) p.action = ACTION_ACCEPT;
      else if (strcmp(str_action, "deny") == 0) p.action = ACTION_DENY;
      else {        
        break;
      }
      
      
      int tag =0;

      prev = pch + 1;
      pch = strchr(pch+1, ' ');
      if (pch) {
        strncpy(str_protocol, prev, pch - prev);
        str_protocol[pch-prev] = 0;
      } else {
        strcpy(str_protocol, prev);
      }
      while (strcmp(str_protocol, "") == 0) {
        prev = pch + 1;
        pch = strchr(pch+1, ' ');
        if (pch) {
          strncpy(str_protocol, prev, pch - prev);
          str_protocol[pch-prev] = 0;
        } else {
          strcpy(str_protocol, prev);
        }
      }
      if (strcmp(str_protocol, "tcp") == 0) p.protocol = PROTO_TCP;
      else if (strcmp(str_protocol, "udp") == 0) p.protocol = PROTO_UDP;
      else if (strcmp(str_protocol, "icmp") == 0) p.protocol = PROTO_ICMP;
      else if (strcmp(str_protocol, "ip") == 0) p.protocol = PROTO_IP;
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
        tag = 1;
        strcpy(str_src, str_protocol);
        p.protocol = PROTO_IP;
        //perror("proto");
      }
      
      strcpy(str_src_mask, "255.255.255.255");
      if (pch) {
        if (!tag) {
          prev = pch + 1;
          pch = strchr(pch+1, ' ');
          if (pch) {
            strncpy(str_src, prev, pch - prev);
            str_src[pch-prev] = 0;
          } else {
            strcpy(str_src, prev);
          }
        }
        if (strcmp(str_src, "host") == 0) {
          prev = pch + 1;
          pch = strchr(pch+1, ' ');
          strncpy(str_src, prev, pch - prev);
          str_src[pch-prev] = 0;
        } else {
          if (strcmp(str_src, "any") == 0) {
          } else {
            prev = pch + 1;
            pch = strchr(pch+1, ' ');
            if (pch) {
              strncpy(str_src_mask, prev, pch - prev);
              str_src_mask[pch-prev] = 0;
            } else {
              strcpy(str_src_mask, prev);
            }
          }
        }
      }
      str2prefix(p.src, str_src, str_src_mask);
      

      p.sport.first = 0;
      p.sport.last = MAX_PORT;
      p.dport.first = 0;
      p.dport.last = MAX_PORT;

      
      strcpy(str_dst, "0.0.0.0");
      strcpy(str_dst_mask, "255.255.255.255");
      if (pch) {
        prev = pch + 1;
        pch = strchr(pch+1, ' ');
        if (pch) {
          strncpy(str_dst, prev, pch - prev);
          str_dst[pch-prev] = 0;
        } else {
          strcpy(str_dst, prev);
        }
        if (strcmp(str_dst, "eq") == 0) {
          prev = pch+1;
          pch = strchr(pch+1, ' ');
          if (pch) {
            strncpy(str_dst_port, prev, pch-prev);
            str_dst_port[pch-prev] = 0;
          }
          p.sport.first = convert_port(str_dst_port);
          p.sport.last = p.sport.first;
          
          prev = pch + 1;
          pch = strchr(pch+1, ' ');
          if (pch) {
            strncpy(str_dst, prev, pch - prev);
            str_dst[pch-prev] = 0;
          } else {
            strcpy(str_dst, prev);
          }        
        }    

        if (strcmp(str_dst, "range") == 0) {
          prev = pch+1;
          pch = strchr(pch+1, ' ');
          if (pch) {
            strncpy(str_dst_port, prev, pch-prev);
            str_dst_port[pch-prev] = 0;
          } else {
            strcpy(str_dst_port, prev);
          }
          p.sport.first = convert_port(str_dst_port);
          prev = pch+1;
          pch = strchr(pch+1, ' ');
          if (pch) {
            strncpy(str_dst_port, prev, pch-prev);
            str_dst_port[pch-prev] = 0;
          } else {
            strcpy(str_dst_port, prev);
          }
          p.sport.last = convert_port(str_dst_port);

          prev = pch + 1;
          pch = strchr(pch+1, ' ');
          if (pch) {
            strncpy(str_dst, prev, pch - prev);
            str_dst[pch-prev] = 0;
          } else {
            strcpy(str_dst, prev);
          }        

        }
      
        if (strcmp(str_dst, "host") == 0) {
          prev = pch + 1;
          pch = strchr(pch+1, ' ');
          if (pch) {
            strncpy(str_dst, prev, pch - prev);
            str_dst[pch-prev] = 0;
          } else {
            strcpy(str_dst, prev);
          }
        } else {
          if (strcmp(str_dst, "any") == 0) {
          } else {
            prev = pch + 1;
            pch = strchr(pch+1, ' ');
            if (pch) {
              strncpy(str_dst_mask, prev, pch - prev);
              str_dst_mask[pch-prev] = 0;
            } else {
              strcpy(str_dst_mask, prev);
            }
          }
        }
      }
      str2prefix(p.dst, str_dst, str_dst_mask);

      if (pch) {
        prev = pch+1;
        pch = strchr(pch+1, ' ');
        if (pch) {
          strncpy(str_dst_port, prev, pch-prev);
          str_dst_port[pch-prev] = 0;
        } else {
          strcpy(str_dst_port, prev);
        }
        if (strcmp(str_dst_port, "eq") == 0) {
          prev = pch+1;
          pch = strchr(pch+1, ' ');
          if (pch) {
            strncpy(str_dst_port, prev, pch-prev);
            str_dst_port[pch-prev] = 0;
          } else {
            strcpy(str_dst_port, prev);
          }
          p.dport.first = convert_port(str_dst_port);
          p.dport.last = p.dport.first;
        } else if (strcmp(str_dst_port, "echo-reply") == 0) {
        } else if (strcmp(str_dst_port, "log") == 0) {
        } else if (strcmp(str_dst_port, "echo") == 0) {
        } else if (strcmp(str_dst_port, "range") == 0) {
          prev = pch+1;
          pch = strchr(pch+1, ' ');
          if (pch) {
            strncpy(str_dst_port, prev, pch-prev);
            str_dst_port[pch-prev] = 0;
          } else {
            strcpy(str_dst_port, prev);
          }
          p.dport.first = convert_port(str_dst_port);
          prev = pch+1;
          pch = strchr(pch+1, ' ');
          if (pch) {
            strncpy(str_dst_port, prev, pch-prev);
            str_dst_port[pch-prev] = 0;
          } else {
            strcpy(str_dst_port, prev);
          }
          p.dport.last = convert_port(str_dst_port);
        } else {
          perror("dport");
        }
      }

      policy_list[nrule] = p;
      policy_list[nrule].router_id = rid;
      policy_list[nrule].acl_num = acl_num;
      policy_list[nrule].entry_index = tmpindex;
      tmpindex ++;

      //cout << "original " << policy_list[nrule] << endl;

      proto_count.insert(policy_list[nrule].protocol);
      sp_count.insert(policy_list[nrule].sport.first);
      sp_count.insert(policy_list[nrule].sport.last);
      dp_count.insert(policy_list[nrule].dport.first);
      dp_count.insert(policy_list[nrule].dport.last);
      range_class r;
      policy_list[nrule].src.getrange(r.first, r.last);
      sip_count.insert(r.first);
      sip_count.insert(r.last);
      policy_list[nrule].dst.getrange(r.first, r.last);
      dip_count.insert(r.first);
      dip_count.insert(r.last);
      
      policy_index_class pindex(nrule, policy_list[nrule].entry_index);
      //router_rules[policy_list[nrule].router_id].push_back(pindex);
      router_interface_class ri(policy_list[nrule].router_id, policy_list[nrule].acl_num);
      rule_group[ri].push_back(pindex);

      //cout << rule_group[ri].size() << " " << policy_list[nrule] << endl;

      //measurement
      acl_per_router[policy_list[nrule].router_id].insert(policy_list[nrule].acl_num);
      
      nrule ++;
      rt = in.getline(str, MAX_STRING_LEN);

    }
    acl_num ++;
  }
}

