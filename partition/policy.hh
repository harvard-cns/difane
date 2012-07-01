#ifndef POLICY_HH
#define POLICY_HH

#include <stdlib.h>
#include "aclparse.hh"
#include "acl.hh"


//protocols
#define PROTO_EIGRP 88
#define PROTO_ESP 50
#define PROTO_GRE 47
#define PROTO_ICMP 1
#define PROTO_IGMP 2
#define PROTO_IPINIP 94
#define PROTO_NOS 4
#define PROTO_OSPF 89
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_IP 255

#define PROTO_PIM 7
#define PROTO_ARP 10
#define PROTO_POP 13
#define PROTO_PCP 14
#define PROTO_AHP 15
#define PROTO_IPV4 16
#define PROTO_BASE 100

//protocol in lightspeed
#define PROTO_VRRP 112
#define PROTO_RSVP 46

//port
#define MAX_PORT 65535

class range_class;

int convert_port(char * str);


class policy_class {
  /*  network                   VARCHAR2(10)   NOT NULL,
    router_name               VARCHAR2(14)   NOT NULL,
    acl_num                   NUMBER         NOT NULL,
    entry_index               NUMBER         NOT NULL,
    acl_date                  DATE           NOT NULL,
    action                    VARCHAR2(8),
    protocol                  VARCHAR2(10),
    src_ip_address            VARCHAR2(16),
    src_mask                  VARCHAR2(16),
    dest_ip_address           VARCHAR2(16),
    dest_mask                 VARCHAR2(16),
    nextfld1                  VARCHAR2(30),
    nextfld2                  VARCHAR2(20),
    nextfld3                  VARCHAR2(20),
  */

public:
  int router_id;
  int acl_num;
  int entry_index;
  char action;
  uint16_t protocol;
  prefix src, dst;
  range_class sport, dport;
  //uint8_t ingress, egress;

  friend ostream& operator<< (ostream &, const policy_class &);
  friend istream& operator>> (istream &, policy_class &);

  void output(ofstream & ofs) {
    uint32_t pfirst, plast;
    uint32_t dfirst, dlast;
    src.getrange(pfirst, plast);
    dst.getrange(dfirst, dlast);

    if (protocol == 255)
      ofs<< "0:255,";
    else
      ofs << protocol << ":" <<protocol << ",";
    
    ofs    << pfirst << ":" << plast << ","
        << sport.first << ":" << sport.last << ","
        << dfirst << ":" << dlast << ","
        << dport.first << ":" << dport.last << ","
        << (int)action << endl;
  }

  
};


class policy_index_class {
public:
  int rule_id;
  int entry_index;
  
  policy_index_class(int rid, int eid) {
    rule_id = rid;
    entry_index = eid;
  }

      policy_index_class& operator=(const policy_index_class& p) {
      rule_id=p.rule_id;
      entry_index=p.entry_index;
      return *this;
    }
    bool operator==(const policy_index_class& p) const {
      if (rule_id ==p.rule_id  && entry_index==p.entry_index) {
        return true;
      }
      else {
        return false;
      }
    }
    bool operator!=(const policy_index_class& p) const {
      if (rule_id ==p.rule_id  && entry_index==p.entry_index) {
        return false;
      }
      else {
        return true;
      }
    }
    bool operator<(const policy_index_class& p) const {
      if (entry_index<p.entry_index) {
        return true;
      }
      else if (entry_index==p.entry_index) {
        return (rule_id <p.rule_id);
      }
      else {
        return false;
      }
    }


};

#endif //POLICY_HH
