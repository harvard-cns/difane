#ifndef ACL_HH
#define ACL_HH

#include <stdlib.h>
#include "util.h"
#include "prefix.h"
#include "binpack.hh"

#define TREE_TYPE_NODE 0
#define TREE_TYPE_LEAF 1
#define TREE_TYPE_PROTO 2
#define TREE_TYPE_SRC 3
#define TREE_TYPE_DST 4
#define TREE_TYPE_SPORT 5
#define TREE_TYPE_DPORT 6

extern int debug;
//extern int tree_file_count;
extern vector<treesize_class> treesize;
//extern int steps;

class tree_node;

string getType(int type);

class router_interface_class {
public:
  int16_t router_id;
  int32_t acl_num;
  router_interface_class() {
    router_id = 0;
    acl_num = 0;
  }
    router_interface_class(int16_t a, int32_t l): router_id(a), acl_num(l) { }
    router_interface_class(const router_interface_class &p) {
      router_id=p.router_id;
      acl_num=p.acl_num;
    }

    void set(int16_t a, int32_t l) {
      router_id=a; acl_num=l;
    }
    router_interface_class& operator=(const router_interface_class& p) {
      router_id=p.router_id;
      acl_num=p.acl_num;
      return *this;
    }
    bool operator==(const router_interface_class& p) const {
      if (router_id ==p.router_id  && acl_num==p.acl_num) {
        return true;
      }
      else {
        return false;
      }
    }
    bool operator!=(const router_interface_class& p) const {
      if (router_id ==p.router_id  && acl_num==p.acl_num) {
        return false;
      }
      else {
        return true;
      }
    }
    bool operator<(const router_interface_class& p) const {
      if (router_id<p.router_id) {
        return true;
      }
      else if (router_id==p.router_id) {
        return (acl_num <p.acl_num);
      }
      else {
        return false;
      }
    }
  bool operator>(const router_interface_class& p) const {
      if (router_id>p.router_id) {
        return true;
      }
      else if (router_id==p.router_id) {
        return (acl_num > p.acl_num);
      }
      else {
        return false;
      }
    }

    friend ostream& operator<< (ostream &, const router_interface_class &);

};


class interface_pair_class {
public:
  router_interface_class from, to;
  interface_pair_class(router_interface_class &a, router_interface_class& b) { 
    from = a;
    to = b;
  }
  interface_pair_class(const interface_pair_class& p) {
      from=p.from;
      to=p.to;
    }
    void set(router_interface_class & a, router_interface_class & l) {
      from=a; to=l;
    }
    interface_pair_class& operator=(const interface_pair_class& p) {
      from=p.from;
      to=p.to;
      return *this;
    }
    bool operator==(const interface_pair_class& p) const {
      if (from ==p.from  && to==p.to) {
        return true;
      }
      else {
        return false;
      }
    }
    bool operator!=(const interface_pair_class& p) const {
      if (from ==p.from  && to==p.to) {
        return false;
      }
      else {
        return true;
      }
    }
    bool operator<(const interface_pair_class& p) const {
      if (from<p.from) {
        return true;
      }
      else if (from==p.from) {
        return (to <p.to);
      }
      else {
        return false;
      }
    }
};

/*class child_class {
public:
  uint32_t range;
  tree_node * pchild;
  };*/
class range_class {
public:
  uint32_t first, last; //[first, last]

  range_class() {
    first = last = 0;
  }
    
  range_class& operator=(const range_class& p) {
      first = p.first;
      last = p.last;
      return *this;
    }
  bool operator==(const range_class& p) const {
    if (first ==p.first  && last==p.last) {
      return true;
    }
    else {
      return false;
    }
  }
  bool operator!=(const range_class& p) const {
    if (first ==p.first  && last==p.last) {
      return false;
    }
    else {
      return true;
    }
  }
  bool operator<(const range_class& p) const {
    if (first<p.first) {
      return true;
    }
    else if (first==p.first) {
      return (last <p.last);
    }
    else {
      return false;
    }
  }

  bool contain(uint32_t value) {
    if (first <= value && value <= last) 
      return true;
    else return false;
  }
  
  int count_prefixes(int type) {
    //if (type == TREE_TYPE_PROTO) 
    //  return 1;
    uint32_t root = first ^ last;
    int count = 0;
    prefix p;
    p.len = 0;
    while (root > 0) {
      p.len ++;
      root = root >> 1;
    }
    p.len = 32 - p.len;
    p.addr = maskbit(first, p.len);
    range_class r, rnew;
    p.getrange(r.first, r.last);
    if (r.last < r.first) 
      cout << *this << " " << r << endl;
    while (p.len < 32 && (r.first < first || r.last > last)) {
      p.len ++;
      p.addr = maskbit(first, p.len);
      p.getrange(r.first, r.last);
    }
    if (p.len > 32) perror("count_prefixes");
    if (first <= r.first && r.last <= last) {
      count ++;
      if (first < r.first) {
        rnew.first = first; 
        rnew.last = r.first - 1;
        count += rnew.count_prefixes(type);
      }
      if (r.last < last) {
        rnew.first = r.last +1;
        if (rnew.first < r.last) return count;
        rnew.last = last;
        count += rnew.count_prefixes(type);
      }
      return count;
    }
    return -1;
  }

  int minus(range_class & p, prefix real) {
    if (first < p.first && p.first <= last && real.addr < p.first)
      last = p.first - 1;
    if (p.last >= first  && p.last < last && real.addr > p.last)
      first = p.last + 1;
    return 1;
  }

  int getprefix(prefix & pnew, prefix real) {
    uint32_t root = first ^ last;
    prefix p;
    p.len = 0;
    while (root > 0) {
      p.len ++;
      root = root >> 1;
    }
    p.len = 32 - p.len;
    p.addr = maskbit(real.addr, p.len);
    range_class r, rnew;
    p.getrange(r.first, r.last);
    if (r.last < r.first) 
      cout << *this << " " << r << endl;
    while (p.len < 32 && (r.first < first || r.last > last)) {
      p.len ++;
      p.addr = maskbit(real.addr, p.len);
      p.getrange(r.first, r.last);
    }
    if (p.len > 32) perror("count_prefixes");
    if (first <= r.first && r.last <= last) {
      pnew = p;
    }
    return -1;
  }


  friend ostream& operator<< (ostream &, const range_class &);
  
};

class tree_node {
public:
  char type;
  char action;
  list<range_class> range;
  map<range_class, tree_node *> child;      

  /*  tree_node() {
    type = TREE_TYPE_NODE;
    action = 0;
    range.init();
    child.init();
    //range.resize(10);
    }*/

  list<range_class>::iterator find_range(uint32_t t) {
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      //cout << *vi << endl;
      if (vi->first <= t && t <=  vi->last) {
        //cout << " hit " << endl;
        return vi;
      }
    }
    return range.end();
  }

  void copy_tree(tree_node * & newtree) {
    if (this == NULL) {
      newtree = NULL;
      return;
    }
    //printf(" thread %lu ", pthread_self());
    //print_onelevel();
    newtree = new tree_node;
    newtree->type= type;
    if (type == TREE_TYPE_LEAF) {
      newtree->action = action;
      return;
    }
    //if (range.size() > 0) 
    //cout << "type ***" << (int)type << "***" << endl;
      newtree->range = range;
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      if (!child[*vi]) continue;
      tree_node * childtmp;
      child[*vi]->copy_tree(childtmp);
      newtree->child[*vi] = childtmp;
    }
  }

  int count_leaves() {
    if (!this) return 0;
    int count = 0;
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      if (!child[*vi]) continue;
      if (child[*vi]->type == TREE_TYPE_LEAF) {
        count ++;
      } else {
        count += child[*vi]->count_leaves();
      }
    }
    return count;
  }

  int count_rules() {
    if (!this) return 0;
    int count = 0;
    /*if (type != TREE_TYPE_PROTO) {
      cout << "hello" << endl;
      }*/
    list<range_class>::iterator vi2 = range.begin();
    if (vi2 == range.end()) return 0;
    vi2 ++;
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      //if (vi2 != range.end() && vi->last + 1 != vi2->first && type != TREE_TYPE_PROTO) 
      //  cout << "wrong" << endl;
      tree_node * tree = child[*vi]; 
      if (!tree) continue;
      if (tree->type == TREE_TYPE_LEAF) {
        if (debug)
        cout << getType(type) << " " << *vi << " " << (int)tree->action << endl;
        count += vi->count_prefixes(type);
      } else {
        if (debug)
        cout << getType(type) << " " << *vi << endl;
        count += vi->count_prefixes(type) * tree->count_rules();
      }
      if (vi2 == range.end()) break;
      vi2 ++;
    }
    return count;
  }

  int add_treesize(unsigned long binsize, int pair_count) {
    if (!this) return 0;
    int count = 0;
    unsigned long size = 0;
    set<unsigned long> sizes;
    int flag = 0;
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      tree_node * tree = child[*vi]; 
      if (!tree) continue;
      size = vi->count_prefixes(type);
      if (tree->type == TREE_TYPE_LEAF) {      
      } else {
        size *= tree->add_treesize(binsize, pair_count);
      }
      if (size < binsize) {
        flag = 1;
        sizes.insert(size);
      }
      count += size;
    }
    /*for (set<unsigned long>::iterator si = sizes.begin(); si != sizes.end(); si ++) {
      cout << *si << endl;
      }*/

    if (flag && (unsigned long)count > binsize) {
      for (set<unsigned long>::iterator si = sizes.begin(); si != sizes.end(); si ++) {
        treesize_class ti;
        ti.count = pair_count; 
        ti.size = *si;
        treesize.push_back(ti);
      }
    }
    return count;
  }

  int count_overlap_rules() {
    if (!this) return 0;
    int count = 0;
    int accept_count = 0, deny_count = 0;
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      tree_node * tree = child[*vi]; 
      if (!tree) continue;
      if (tree->type == TREE_TYPE_LEAF) {
        if (tree->action == ACTION_ACCEPT)
          accept_count += vi->count_prefixes(type);
        else deny_count += vi->count_prefixes(type);
      } else {
        if (tree->action == ACTION_ACCEPT)
          accept_count += vi->count_prefixes(type) * tree->count_rules();
        else deny_count += vi->count_prefixes(type) * tree->count_rules();
      }
    }
    count = (accept_count < deny_count)?accept_count:deny_count;
    return count;
  }

  int print() {
    cout << "+++++++++" << endl;
    if (!this) return 0;
    int count = 0;
    list<range_class>::iterator vi2 = range.begin();
    if (vi2 == range.end()) return 0;
    vi2 ++;
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      tree_node * tree = child[*vi]; 
      if (!tree) continue;
      if (tree->type == TREE_TYPE_LEAF) {
        cout << getType(type) << " " << *vi << " " << (int)tree->action << endl;
        count += vi->count_prefixes(type);
      } else {
        cout << getType(type) << " " << *vi << endl;
        count += vi->count_prefixes(type) * tree->print();
      }
      if (vi2 == range.end()) break;
      vi2 ++;
    }
    cout << "---------" << endl;
    return count;
  }

  int write_file(ofstream & oftree) {
    if (!this) {
      oftree << "0 0 0" << endl;
      return 0;
    }
    if (type == TREE_TYPE_LEAF) {
      oftree << (int)type << " 0 0" << endl;
      oftree << (int)action << endl;
      oftree << "0 0 0" << endl;
      //cout << (int)action << endl;
    } 
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      tree_node * tree = child[*vi]; 
      if (!tree) continue;
      oftree << (int)type << " " << vi->first << " " << vi->last << endl;
      //cout << (int)type << " " << vi->first << " " << vi->last << endl;
      if (type == TREE_TYPE_LEAF) {
        oftree << (int)action << endl;
        //cout << (int)action << endl;
      } else {
        tree->write_file(oftree);
      }
    }
    oftree << "0 0 0" << endl;
    return 0;
  }

  int read_file(ifstream & iftree) {
    char str[1000];
    range_class r;
    int count = 0;
    int tmptype;
    //steps ++;
    //if (steps > 6) 
    //  cout << steps << " hello" << endl;
    while (iftree.getline(str, MAX_STRING_LEN)) {
      sscanf(str, "%d %u %u", &tmptype, &r.first, &r.last);
      count ++;
      if (tmptype == 0) {
        //steps --;
        //cout << " 0 0  0" << endl;
        if (count == 1) return -1;
        else 
          return 0;
      }
      type = tmptype;
      //cout << "type " << getType(type) << " " << r << endl;
      if (type == TREE_TYPE_LEAF) {
        iftree.getline(str, MAX_STRING_LEN);
        action = atoi(str);
      } else {
        range.push_back(r);
      }
      tree_node * tmp = new tree_node;
      int result = tmp->read_file(iftree);
      if (result < 0) {
        delete tmp;
        tmp = NULL;
      }
      child[r] = tmp;
    }
    return 0;
  }

  int print_onelevel() {
    if (!this) return 0;
    if (type == TREE_TYPE_LEAF) {
      cout << getType(type) << " " << *range.begin() << " " << (int)action << endl;
      return 0;
    }
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      tree_node * tree = child[*vi]; 
      if (!tree) continue;
      if (tree->type == TREE_TYPE_LEAF) {
        cout << getType(type) << " " << *vi << " " << (int)tree->action << endl;
      } else {
        cout << getType(type) << " " << *vi << endl;
      }
    }
    return 0;
  }

  void delete_tree() {
    if (!this) return;
    if (type != TREE_TYPE_LEAF) {
      //if (type == TREE_TYPE_DST) {
      /* cout << "delete tree" << endl;
        print_onelevel();
        cout << "finish delete print" << endl;*/
        //}
      for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
        //if (child.find(*vi) == child.end()) continue;
        tree_node * tree = child[*vi]; 
        if (tree) tree->delete_tree();
      }
    }
    delete this;
    return;
  }

  bool equal(tree_node * tree) {
    if (tree == NULL && this == NULL) return true;
    if (!tree || !this) return false;
    if (tree->type != type) return false;
    if (type == TREE_TYPE_LEAF) {
      if (action == tree->action) return true;
      else return false;
    }
    if (tree->range.size() != range.size())  return false;
    list<range_class>::iterator vi2 = tree->range.begin();
    if (vi2 == range.end()) return true;
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      if (*vi != *vi2) return false;
      tree_node * node = child[*vi], * node2 = tree->child[*vi2]; 
      if (!node || !node2) continue;
      if (!node->equal(node2)) return false;
      if (vi2 == range.end()) break;
      vi2 ++;
    }
    return true;
  }

  int findsame(tree_node * tree) {
    if (tree == NULL && this == NULL) return 0;
    if (!tree || !this) return 0;
    if (tree->type != type) return 0;
    if (type == TREE_TYPE_LEAF) {
      if (action == tree->action) return 1;
      else return 0;
    }

    int count = 0;
    for (list<range_class>::iterator vi2 = range.begin(); vi2 != range.end(); vi2 ++) {
      for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
        if (vi->first == vi2->first && vi->last == vi2->last) {
          count += vi->count_prefixes(type)*child[*vi]->findsame(child[*vi2]);
        }
      }
    }
    return true;
  }


  bool common(tree_node * tree, list<range_class>::iterator & vi1, list<range_class>::iterator & vi2) {
    if (!tree || !this) return false;
    if (tree->type != type) return false;
    if (type == TREE_TYPE_LEAF || tree->type == TREE_TYPE_LEAF) {
      return false;
    }
    vi2 = tree->range.begin();
    vi1 = range.begin();
    while (vi1 != range.end() && vi2 != tree->range.end()) {
      if (vi1-> first < vi2->first) {
        vi1 ++;
        continue;
      }
      if (vi1-> first > vi2->first) {
        vi2 ++;
        continue;
      }
      if (vi1->first == vi2->first && vi1->last != vi2->last) {
        vi1++; 
        if (vi1->first > vi2->first ) continue;
        if (vi1->last != vi2->last) {
          vi1 --;
          vi2 ++;
          if (vi2->first > vi1->first) continue;
          if (vi1->last != vi2->last) {
            vi1 ++; continue;
          }
        }
      }
      if (child[*vi1]->equal(tree->child[*vi2]))
        return true;
    }
    return false;
  }

  void merge_tree() {
    if (!this) return;
    if (type == TREE_TYPE_LEAF) return;
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      tree_node * tree = child[*vi];
      tree->merge_tree();
    }
    
    //this->print();
    bool merge = true;
    while (merge) {
      /* if (type == TREE_TYPE_SRC) {
        cout << "tree start" << endl;
        print();
        cout << "tree end " << endl;
        }*/
      merge = false;
      list<range_class>::iterator vi2 = range.begin();
      if (vi2 == range.end()) break;
      vi2 ++;
      for (list<range_class>::iterator vi = range.begin(); vi!= range.end(); vi ++) {
        if (vi2 == range.end()) break;
        if (vi->last +1 > 0 && vi->last + 1 == vi2->first && vi2->first > vi->last) {
          tree_node * node1 = child[*vi], * node2 = child[*vi2];
          if (node1->equal(node2)) {
            range_class r;
            r.first = vi->first;
            r.last = vi2->last;
            child[r] = child[*vi];
            range.push_back(r);
            range.remove(*vi2);
            range.remove(*vi);
            range.sort();
            if (child[*vi2]) {
              //cout << *vi << " " << *vi2 << endl;
              child[*vi2]->delete_tree();
            }
            child[*vi2] = NULL;
            merge = true;
            break;
          }
        }        
        if (vi2 == range.end()) break;
        vi2 ++;
      }
    }

  }

  int count_duplicates() {
    if (!this) return 0;
    if (type == TREE_TYPE_LEAF) return 0;
    int count = 0;
    for (list<range_class>::iterator vi = range.begin(); vi != range.end(); vi ++) {
      tree_node * tree = child[*vi];
      count += vi->count_prefixes(type)*tree->count_duplicates();
    }
    
      list<range_class>::iterator vi2 = range.begin();
      if (vi2 == range.end()) return count;
      vi2 ++;
      for (list<range_class>::iterator vi = range.begin(); vi!= range.end(); vi ++) {
        if (vi2 == range.end()) break;
        if (vi->last + 1 == vi2->first && vi2->first > vi->last) {
          tree_node * node1 = child[*vi], * node2 = child[*vi2];
          count += node1->findsame(node2);
        }
        if (vi2 == range.end()) break;
        vi2 ++;
      }

    return count;
  }

};

#endif //ACL_HH
