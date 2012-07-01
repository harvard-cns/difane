#ifndef ACLPARSE_HH
#define ACLPARSE_HH

#include "util.h"

#include "prefix.h"
#include "policy.hh"
#include "readfile.hh"
#include "interface.hh"
#include "link.hh"
#include "acl.hh"

extern int nrouter;
extern int file_format;
extern map<string, int> routermap;
//extern policy_class * policy_list;

extern char str[MAX_STRING_LEN];

extern int nrule ;
extern map<router_interface_class, tree_node *> router_tree;

//measurement
extern set<int> acl_per_router[MAX_ROUTER];

class add_interface_args {
public:
  router_interface_class ri;
  tree_node * tmp;
};

class create_path_args {
public:
  int i, j;
};

class tree_file_class{
public:
  int from, to;
  int out_acl;

  tree_file_class() {
    from = 0;
    to = 0;
    out_acl = 0;
  }
  tree_file_class(int a, int b, int c): from(a), to(b), out_acl(c) { }
    tree_file_class(const tree_file_class& p) {
      from=p.from;
      to=p.to;
      out_acl = p.out_acl;
    }
  void set(int a, int b, int c) {
    from=a; to=b; out_acl = c;
  }
    tree_file_class& operator=(const tree_file_class& p) {
      from=p.from;
      to=p.to;
      out_acl = p.out_acl;
      return *this;
    }
    bool operator==(const tree_file_class& p) const {
      if (from ==p.from  && to==p.to && out_acl == p.out_acl) {
        return true;
      }
      else {
        return false;
      }
    }
    bool operator!=(const tree_file_class& p) const {
      if (from ==p.from  && to==p.to && out_acl == p.out_acl) {
        return false;
      }
      else {
        return true;
      }
    }
    bool operator<(const tree_file_class& p) const {
      if (to<p.to) {
        return true;
      }
      else if (to==p.to) {
        if (from <p.from) {
          return true;
        } else if (from == p.from) {
          return (out_acl < p.out_acl);
        } else {
          return false;
        }
      }
      else {
        return false;
      }
    }
};

class ripair_class {
public: 
  router_interface_class from, to;

  ripair_class() {
  }

    ripair_class(router_interface_class rifrom, router_interface_class rito) {
    from = rifrom;
    to = rito;
  }

      ripair_class& operator=(const ripair_class& p) {
      from=p.from;
      to=p.to;
      return *this;
    }
    bool operator==(const ripair_class& p) const {
      if (from ==p.from  && to==p.to) {
        return true;
      }
      else {
        return false;
      }
    }
    bool operator!=(const ripair_class& p) const {
      if (from ==p.from  && to==p.to) {
        return false;
      }
      else {
        return true;
      }
    }
    bool operator<(const ripair_class& p) const {
      if (to<p.to) {
        return true;
      }
      else if (to==p.to) {
        return (from <p.from);
      }
      else {
        return false;
      }
    }
};

string get_router(int i);

#endif
