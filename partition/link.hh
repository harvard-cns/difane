#ifndef LINK_HH
#define LINK_HH

#include "prefix.h"
#include "util.h"
#include "aclparse.hh"

class link_class {
  /*
    network                   VARCHAR2(10)   NOT NULL,
    network_ip                VARCHAR2(16)   NOT NULL,
    mask                      NUMBER         NOT NULL,
    router_date               DATE           NOT NULL,
    router1                   VARCHAR2(14)   NOT NULL,
    card1                     VARCHAR2(26)   NOT NULL,
    router2                   VARCHAR2(14)   NOT NULL,
    card2                     VARCHAR2(26)   NOT NULL,
    speed1                    NUMBER         NOT NULL,
    speed2                    NUMBER         NOT NULL,
    PRIMARY KEY (network, network_ip, mask, router_date)
  */

public:
  prefix link;
  int16_t router1, router2;

  friend ostream& operator<< (ostream &, const link_class &);
  friend istream& operator>> (istream &, link_class &);

};

class acl_link_class {
public:
  int32_t acl1, acl2;
  acl_link_class() {
    acl1 = acl2 = -1;
  }
};

#endif
