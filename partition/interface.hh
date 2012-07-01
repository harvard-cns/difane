#ifndef INTERFACE_HH
#define INTERFACE_HH

#include "aclparse.hh"

class interface_class {

  /*
    network                   VARCHAR2(10)     NOT NULL,
    router_name               VARCHAR2(14)     NOT NULL,
    card                      VARCHAR2(26)     NOT NULL,
    interface_date            DATE             NOT NULL,
    interface_type            VARCHAR2(20),
    interface_ip              VARCHAR2(16),
    interface_mask            VARCHAR2(16),
    description               VARCHAR2(120),
    shutdown                  VARCHAR2(2),
    encapsulation             VARCHAR2(20),
    ospf_weight               VARCHAR2(6),
    in_access_group           VARCHAR2(6),
    out_access_group          VARCHAR2(6),
    dsu_bandwidth             VARCHAR2(7),
    bandwidth                 VARCHAR2(7),
    mtu                       VARCHAR2(6),
    cablelength               VARCHAR2(4),
    crc                       VARCHAR2(3),
    framing                   VARCHAR2(6),
    cdp                       VARCHAR2(2),
    clock_si                  VARCHAR2(2),
    dir_broadcast             VARCHAR2(2),
    netflow                   VARCHAR2(2)
    PRIMARY KEY (network, router_name, card, interface_date)
*/

public:
  prefix interface;
  int16_t router_id;
  int32_t ospf_weight;
  int32_t in_acl, out_acl;

  char type;
  interface_class() {
    router_id = -1;
    in_acl = out_acl = -1;
  }
  
    interface_class& operator=(const interface_class& p) {
      router_id=p.router_id;
      ospf_weight=p.ospf_weight;
      in_acl = p.in_acl;
      out_acl = p.out_acl;
      return *this;
    }
    bool operator==(const interface_class& p) const {
      if (router_id ==p.router_id  && ospf_weight==p.ospf_weight && in_acl == p.in_acl && out_acl == p.out_acl) {
        return true;
      }
      else {
        return false;
      }
    }
    bool operator!=(const interface_class& p) const {
      if (router_id ==p.router_id  && ospf_weight==p.ospf_weight && in_acl == p.in_acl && out_acl == p.out_acl) {
        return false;
      }
      else {
        return true;
      }
    }
    bool operator<(const interface_class& p) const {
      if (ospf_weight<p.ospf_weight) {
        return true;
      }
      else if (ospf_weight==p.ospf_weight) {
        return (router_id <p.router_id);
      }
      else {
        return false;
      }
    }



  friend ostream& operator<< (ostream &, const interface_class &);
  friend istream& operator>> (istream &, interface_class &);

};


#endif
