#include "util.h"

#include <sys/types.h>
#include <sys/wait.h>

#include "aclparse.hh"
#include "binpack.hh"
#include "cube.hh"
#include "packet.hh"

//#define PARALLEL 1

int nrouter = 0;
int file_format = FORMAT_EXT;
map<string, int> routermap;
policy_class * policy_list = new policy_class[MAX_POLICY_COUNT];

//input parameters
char directory[100];

//for partition cubes
char tmpaclfile[100];
char statsfile[100];
char csvfile[100];

//tree files
int tree_file_count = 0;
map<tree_file_class, int> tree_file_map;

//shortest path ACL list
map<set<router_interface_class>, set<ripair_class> > rimap;
map<tree_file_class, set<router_interface_class> > ri_path_map;

//network
vector<interface_class> interface_set[MAX_ROUTER];
int nlink = 0;
Link link_list[MAX_LINK];
acl_link_class * acl_link_list;
ShortestPath* spath;

policy_class policy;
char str[MAX_STRING_LEN];

int switchsize = 0, ncut = 0;

long totalrules = 1000000;

int nrule = 0;
map<router_interface_class, vector<policy_index_class> > rule_group;
map<router_interface_class, tree_node *> router_tree;
//pthread_mutex_t * router_tree_mutex;
map<router_interface_class, pthread_mutex_t> router_tree_mutex;
pthread_t * threads;
pthread_mutex_t file_mutex;

map<interface_pair_class, tree_node *> network_tree;

//measurement
set<int> acl_per_router[MAX_ROUTER];
set<uint32_t> proto_count, sp_count, dp_count, sip_count, dip_count;

enum schemetype {SCHEME_ONESWITCH, SCHEME_NETWORK, SCHEME_BINPACK, SCHEME_PARTITION, SCHEME_CACHE};
schemetype runscheme = SCHEME_PARTITION;
int   network = NETWORK_CBB;

//for debug
int debug = 0;
//int steps= 0;

char fnetfilename[255];
ofstream fnetacl;

//for BinPack
vector<treesize_class> treesize;

  char filename[100];

  
  unsigned long binsize = 10000000;


  int incount = 0, outcount = 0;


int addinfo(tree_node * root, tree_node * newroot, 
            tree_node * curr, tree_node * newcurr, 
            range_class * range, range_class * newrange, 
            int step, int newstep);

bool isEmpty(router_interface_class ri) {
  if (ri.acl_num < 0) return true;
  if (rule_group[ri].size() == 0) return true;
  return false;
}

string get_router(int i) {
  if (network == NETWORK_CAMPUS) {
    return "campus";
  }
  for (map<string, int>::iterator mi = routermap.begin(); mi != routermap.end(); mi ++) {
    if (mi->second == i) return mi->first;
  }
  return NULL;
}
    
void init_tree(tree_node * root) {
  //protocol
  root = NULL;
  /* root = new tree_node;
  range_class r;
  r.last = MAX_PROTO;
  r.first = 0;
  root->range.push_back(r);
  tree_node * src = new tree_node;
  root->child[MAX_PROTO] = src;
  
  //src
  r.last = MAX_ADDR;
  src->range.push_back(r);
  tree_node * dst = new tree_node;
  src->child[MAX_ADDR] = dst;
  
  //dst
  dst->range.push_back(r);
  dst->child[MAX_ADDR] = NULL;
  */
}

void search_leaf(tree_node * & root, policy_class &p, range_class range, int type) {
  range_class r = range;
  uint32_t pfirst = r.first;
  uint32_t plast = r.last;

  if (root == NULL) {
    root = new tree_node;
    root->range.push_back(r);
    tree_node * tmp = new tree_node;
    root->type = type;
    root->child[r] = tmp;
    tmp->type = TREE_TYPE_LEAF;
    tmp->action = p.action;
    return;
  }

  uint32_t tmplast;

  /*for (vector<range_class>::iterator ti = root->range.begin(); ti != root->range.end(); ti ++) {
          cout << *ti << endl;
          }*/

  int overflow = 0;

  //sort(root->range.begin(), root->range.end());
  //root->range.sort();
    list<range_class>::iterator rangeend = root->range.end();
    for (list<range_class>::iterator vi = root->range.begin(); vi != rangeend; vi ++) {
      if (vi->first > plast) break;
      if (vi->first == pfirst) {
        pfirst = vi->last + 1;
        if (pfirst < vi->last) {
          overflow= 1;
          break;
        }        
        continue;
      }
      if (vi->first < pfirst && plast <= vi->last) {
        pfirst = vi->last + 1;
        if (pfirst < vi->last) {
          overflow= 1;
          break;
        }
        continue;
      }
      if (vi->first > pfirst && vi->first <= plast) {
        tmplast = vi->last;
        r.first = pfirst;
        r.last = vi->first - 1;
        root->range.push_back(r);
 
        /*for (list<range_class>::iterator ti = root->range.begin(); ti != root->range.end(); ti ++) {
          cout << *ti << endl;
          }*/

        root->child[r] = new tree_node;
        root->child[r]->type = TREE_TYPE_LEAF;
        root->child[r]->action = p.action;
        
        pfirst = tmplast + 1;
        if (pfirst < tmplast) {
          overflow = 1;
          break;
        }
        continue;
      }
      if (pfirst > plast) break;
    }

  if (pfirst <= plast && !overflow) {
      r.first = pfirst;
      r.last = plast;
      root->range.push_back(r);
      root->child[r] = new tree_node;
      root->child[r]->type = TREE_TYPE_LEAF;
      root->child[r]->action = p.action;
  }
  
  root->range.sort();
}

void search_sport(tree_node * & root, policy_class &p, int);
void search_dport(tree_node * & root, policy_class &p, int);
void search_protocol(tree_node * & root, policy_class & p, int);
void search_src(tree_node * & root, policy_class & p, int);
void search_dst(tree_node * & root, policy_class &p, int index);

void searchfunc(tree_node * & root, policy_class &p, int index) {
  switch (index) {
  case 0: search_src(root, p, index+1);
    break;
  case 1: search_dst(root, p, index+1);
    break;
  case 2: search_sport(root, p, index+1);
    break;
  case 3: search_protocol(root, p, index+1);
    break;
  case 4: search_dport(root, p, index+1);
    break;
  }
}

void search_range(tree_node * & root, policy_class & p, range_class range, int type, int index) {
  if (index == 5) search_leaf(root, p, range, type);

  int overflow = 0;
  tree_node * treetmp;

  uint32_t pfirst = range.first, plast = range.last;
  
  //if (pfirst == plast && pfirst == 2677604352)
  //  cout << "hello word " << endl;
  if (root == NULL) {
    root = new tree_node;
    root->type = type;
    root->range.push_back(range);
    root->child[range] = NULL;
    searchfunc(root->child[range], p, index);
    return;
  }

  //sort(root->range.begin(), root->range.end());
  //root->range.sort();
  list<range_class>::iterator rangeend = root->range.end();
  list<range_class> rangeerase;
  range_class r;
  for (list<range_class>::iterator vi = root->range.begin(); vi != rangeend; vi ++) {
    uint32_t tmpfirst = vi->first, tmplast = vi->last;
    if (vi->first > plast) break;
    if (tmpfirst < pfirst && tmplast >= pfirst && tmplast <= plast) {
      rangeerase.push_back(*vi);
      r.first = pfirst;
      r.last = tmplast;
      root->range.push_back(r);
      root->child[r] = root->child[*vi];
      r.first = tmpfirst;
      r.last = pfirst - 1;
      root->range.push_back(r);
      root->child[*vi]->copy_tree(treetmp);
      root->child[r]=treetmp;
      searchfunc(root->child[*vi], p, index);
      root->child[*vi] = NULL;

      pfirst = tmplast + 1; 
      if (pfirst  < tmplast) {
        overflow = 1;
        break;
      }
      
      if (pfirst > plast) break;
      else continue;
    }
    if (tmpfirst < plast && tmplast >= plast && tmpfirst > pfirst) {
      rangeerase.push_back(*vi);
      r.first = plast +1;
      r.last = tmplast;
      root->range.push_back(r);
      root->child[r] = root->child[*vi];
      r.first = tmpfirst;
      r.last = plast;
      root->range.push_back(r);
      root->child[*vi]->copy_tree(treetmp);
      root->child[r]=treetmp;
      searchfunc(root->child[r], p, index);

      root->child[*vi] = NULL;
      break;
    }
    if (tmpfirst < pfirst && tmplast > plast) {
      rangeerase.push_back(*vi);
      r.first = plast + 1;
      r.last = tmplast;
      root->range.push_back(r);
      root->child[r] = root->child[*vi];

      r.first = tmpfirst;
      r.last = pfirst - 1;
      root->range.push_back(r);
      root->child[*vi]->copy_tree(treetmp);
      root->child[r] = treetmp;

      r.first = pfirst;
      r.last = plast;      
      root->range.push_back(r);
      root->child[*vi]->copy_tree(treetmp);
      root->child[r] = treetmp;
    
      searchfunc(treetmp, p, index);
      pfirst = plast + 1;
      if (pfirst < plast) overflow = 1;
      break;
    }
    if (pfirst == tmpfirst) {
      if (plast <= tmplast) {
        searchfunc(root->child[*vi], p, index);
        pfirst = tmplast + 1;
        if (pfirst < tmplast) overflow = 1;
        break;
      }
    }
    if (pfirst <= tmpfirst && plast >= tmplast) {
      if (pfirst < tmpfirst) {
        r.first = pfirst;
        r.last = tmpfirst - 1;
        root->range.push_back(r);
        root->child[r] = NULL;
        searchfunc(root->child[r], p, index);
      }
      
      searchfunc(root->child[*vi], p, index);
    
      pfirst = tmplast + 1;
      if (pfirst < tmplast) {
        overflow = 1;
        break;
      }
      if (pfirst > plast) break;
      else continue;
    }
  }

  if (pfirst <= plast && !overflow) {
    r.first = pfirst;
    r.last = plast;
    root->range.push_back(r);
    root->child[r] = NULL;
    searchfunc(root->child[r], p, index);
  }

  for (list<range_class>::iterator tmpr = rangeerase.begin(); tmpr != rangeerase.end(); tmpr ++) {
    root->range.remove(*tmpr);
  }

  if (root->range.size() > 0) {
    root->range.sort();
  }

}

void search_dst(tree_node * & root, policy_class &p, int index) {
  uint32_t pfirst, plast;
  if (debug)
    cout << "hello" << endl;
  p.dst.getrange(pfirst, plast);
  range_class r;
  r.first = pfirst;
  r.last = plast;

  //search_leaf(root, p, r, TREE_TYPE_DST);
  search_range(root, p, r, TREE_TYPE_DST, index);
  
}

void search_src(tree_node * & root, policy_class &p, int index) {
  uint32_t pfirst, plast;
  p.src.getrange(pfirst, plast);
  range_class r;
  r.first = pfirst;
  r.last = plast;

  search_range(root, p, r, TREE_TYPE_SRC, index);
  //search_leaf(root, p, r, TREE_TYPE_SRC);
}

void search_dport(tree_node * & root, policy_class &p, int index) {
  //search_range(root, p, p.dport, search_protocol, TREE_TYPE_DPORT);
  search_range(root, p, p.dport, TREE_TYPE_DPORT, index);
}

void search_sport(tree_node * & root, policy_class &p, int index) {
  search_range(root, p, p.sport, TREE_TYPE_SPORT, index);
}


void search_protocol(tree_node * & root, policy_class & p, int index) {
  range_class r;
  r.first = p.protocol;
  r.last = p.protocol;
 
  if (p.protocol == PROTO_IP) {
    r.first = 0;
    r.last = 255;
  }

  search_range(root, p, r, TREE_TYPE_PROTO, index);
  
  /* uint32_t value = p.protocol;
  
  list<range_class>::iterator vi, vierase = root->range.end();
  if (root) {
    vi = root->find_range(value);
  }
  if (root == NULL || vi == root->range.end()) {
    if (!root) root = new tree_node;
    range_class r;
    r.first = value;
    r.last = value;
    root->type = TREE_TYPE_PROTO;
    root->range.push_back(r);
    root->child[r] = NULL;
    search_src(root->child[r], p);
    sort(root->range.rbegin(), root->range.rend());
    return;
  }
  
  map<uint32_t, tree_node *>::iterator mi = root->child.find(vi->last);

  if (value == vi->last && value == vi->first) {
    search_src(mi->second, p);
    return;
  }

  if (value > vi->first && value == vi->last) {
    vi->last = value - 1; 
    root->child[value-1] = root->child[value];
  } 

  if (value == vi->first && value < vi->last) {
    vi->first = value +1;
  }

  if (value > vi->first && value < vi->last) {
    vi->first = value + 1;
    tree_node * newtree;
    root->child[vi->last]->copy_tree(newtree);
    root->child[value-1] = newtree;
  }

  range_class r;
  r.first = value; r.last = value;
  root->child[value] = NULL;
  root->range.push_back(r);
  search_src(root->child[value], p);
  sort(root->range.rbegin(), root->range.rend());

  */

  return;
}

void create_tree_for_router(tree_node * & root, vector<policy_index_class> & rules, policy_class & defaultp) {
  root = NULL;


  for (vector<policy_index_class>::iterator vi = rules.begin(); vi != rules.end(); vi ++) {
    //if (vi->rule_id  == 66) {
      //if (policy_list[vi->rule_id].router_id > 52) {
    //#ifdef DEBUG
    //if (vi->rule_id > 8000000)
    //cout << vi->rule_id << ":" << policy_list[vi->rule_id] << endl;
    //#endif
    // }
    searchfunc(root, policy_list[vi->rule_id], 0);
  }

  searchfunc(root, defaultp, 0);
}

range_class r1[10], r2[10];
void add_interface(tree_node * &tmp, int router_id, int acl_num) {
  router_interface_class ri(router_id, acl_num);
  if (ri.acl_num < 0) {
    tmp = NULL;
    return;
  }
  if (rule_group[ri].size() == 0) {
    tmp = NULL;
    return;
  }
  /*if (rule_group[ri].size() == 0) {
    cout << ri << " " << get_router(ri.router_id) << endl;
    exit(0);
    }*/
  tree_node * tmp1 = NULL;

#ifdef PARALLEL
  if (router_tree_mutex.find(ri) == router_tree_mutex.end()) {
    pthread_mutex_init(&router_tree_mutex[ri], NULL);
  }
  pthread_mutex_lock(&router_tree_mutex[ri]);
#endif

  if (!router_tree[ri]) {
    policy_class defaultp;
    defaultp.router_id = 0;
    defaultp.acl_num = 0;
    defaultp.entry_index = 99999;
    defaultp.action = ACTION_DENY;
    defaultp.protocol = PROTO_IP;
    defaultp.src.addr = 0;
    defaultp.src.len  =0;
    defaultp.dst.addr = 0;
    defaultp.dst.len  =0;
    defaultp.sport.first = 0;
    defaultp.sport.last = MAX_PORT;
    defaultp.dport.first = 0;
    defaultp.dport.last = MAX_PORT;

    defaultp.router_id = ri.router_id;
    defaultp.acl_num = ri.acl_num;
    sort(rule_group[ri].begin(), rule_group[ri].end());
    create_tree_for_router(tmp1, rule_group[ri], defaultp);
    //tmp1->print();    
    if (tmp1) tmp1->merge_tree();
    router_tree[ri] = tmp1;
  } else {
    tmp1 = router_tree[ri];
  }

  if (tmp) {    
    addinfo(tmp, tmp1, tmp, tmp1, r1, r2, 0, 0);
    //if (tmp1) tmp1->delete_tree();
  } else {
    if (tmp1) tmp1->copy_tree(tmp);
  }

#ifdef PARALLEL
  pthread_mutex_unlock(&router_tree_mutex[ri]);
#endif
  
}

void get_interface(tree_node * &tmp, router_interface_class &ri) {
  if (ri.acl_num < 0) {
    tmp = NULL;
    return;
  }
  if (rule_group[ri].size() == 0) {
    tmp = NULL;
    return;
  }
  /*if (rule_group[ri].size() == 0) {
    cout << ri << " " << get_router(ri.router_id) << endl;
    exit(0);
    }*/
  tree_node * tmp1 = NULL;

#ifdef PARALLEL
  if (router_tree_mutex.find(ri) == router_tree_mutex.end()) {
    pthread_mutex_init(&router_tree_mutex[ri], NULL);
  }
  pthread_mutex_lock(&router_tree_mutex[ri]);
#endif

  if (!router_tree[ri]) {
    policy_class defaultp;
    defaultp.router_id = 0;
    defaultp.acl_num = 0;
    defaultp.entry_index = 9999;
    defaultp.action = ACTION_DENY;
    defaultp.protocol = PROTO_IP;
    defaultp.src.addr = 0;
    defaultp.src.len  =0;
    defaultp.dst.addr = 0;
    defaultp.dst.len  =0;
    defaultp.sport.first = 0;
    defaultp.sport.last = MAX_PORT;
    defaultp.dport.first = 0;
    defaultp.dport.last = MAX_PORT;

    defaultp.router_id = ri.router_id;
    defaultp.acl_num = ri.acl_num;
    sort(rule_group[ri].begin(), rule_group[ri].end());
    create_tree_for_router(tmp1, rule_group[ri], defaultp);
    //tmp->print();    
    if (tmp1) tmp1->merge_tree();
    router_tree[ri] = tmp1;
  } else {
    tmp1 = router_tree[ri];
  }

  tmp = tmp1;
  
#ifdef PARALLEL
  pthread_mutex_unlock(&router_tree_mutex[ri]);
#endif
  
}

void * create_path_acl(void * pathargs) {
  int i, j;
  i = ((create_path_args *) pathargs)->i;
  j = ((create_path_args *) pathargs)->j;
  printf("thread %lu", pthread_self());
  cout << " thread " << pthread_self() << " * router " << i << " " << j << " " << get_router(i) << " " << get_router(j) << endl;
  int from = i, next;
  //int aclcount = 0, hopcount = 0;
  //cout << get_router(i) << " ";
  tree_node * tmp = NULL;
  while (from != j && spath[from*nrouter+j].length < MAX_DOUBLE) {
    //hopcount ++;     
    next = spath[from*nrouter+j].next;
    router_interface_class ri(from, acl_link_list[from*nrouter+next].acl1), ri2(next, acl_link_list[from*nrouter+next].acl2);
    add_interface(tmp, ri.router_id, ri.acl_num);
    add_interface(tmp, ri2.router_id, ri2.acl_num);
    
    //cout << get_router(next) << " ";
    /*if (acl_link_list[from*nrouter + next].acl1 >= 0) 
      aclcount ++;
      if (acl_link_list[from*nrouter + next].acl2 >= 0) 
          aclcount ++;*/
    from = next;
  }
  if (from == j) {
    if (tmp) {
      cout << i << " ---> " << j << endl;
      //tmp->print();
    }            
    //exit(0);
    
    //fpath << hopcount << endl;
    //fpathacl << aclcount << endl;
  }
  
  //find ingress/egress interface
  int flag = 0;
  for (vector<interface_class>::iterator si = interface_set[i].begin(); si != interface_set[i].end(); si ++) {
    if (si->type == INTERFACE_INTERNAL) continue;
    router_interface_class ri(i, si->in_acl);
    tree_node * tmp2 = NULL;
    if (si->in_acl < 0 || rule_group[ri].size() == 0) {
      if (flag) continue;
      flag = 1;
    }
    tmp->copy_tree(tmp2);
    add_interface(tmp2, ri.router_id, ri.acl_num);
    for (vector<interface_class>::iterator si2 = interface_set[j].begin(); si2 != interface_set[j].end(); si2++) {
      //cout << " si " << *si2 << endl;
      if (si2->type == INTERFACE_INTERNAL) continue;
      router_interface_class ri2(j, si2->out_acl);
      tree_node * tmp3 = NULL;
      tmp2->copy_tree(tmp3);
      add_interface(tmp3, ri2.router_id, ri2.acl_num);
      //interface_pair_class ipair(ri, ri2);
      if (tmp3) tmp3->merge_tree();
      //network_tree[ipair] = tmp3;
      if (tmp3) {
        int ruletmp = tmp2->count_rules();
        pthread_mutex_lock(&file_mutex);
        fnetacl.open(fnetfilename, ios_base::app);
        fnetacl << ruletmp << endl;
        fnetacl.close();
        pthread_mutex_unlock(&file_mutex);
        if (tmp3) tmp3->delete_tree();
      }
    }
    if (tmp2) tmp2->delete_tree();
  }
  
  if (tmp) tmp->delete_tree();
  return NULL;
}

set<router_interface_class> get_ri_on_path(int from, int router_id, int acl_num) {
  router_interface_class to(router_id, acl_num);
  tree_file_class tc;
  tc.from = from; 
  tc.to = to.router_id;
  tc.out_acl = to.acl_num;
  set<router_interface_class> tmp;
  if (ri_path_map.find(tc) == ri_path_map.end()) {
    if (from == to.router_id) {
      if (!isEmpty(to)) tmp.insert(to);
      return tmp;
    }
    
    int next = spath[from*nrouter+to.router_id].next;
    tmp = get_ri_on_path(next, to.router_id, to.acl_num);
    router_interface_class ri(from, acl_link_list[from*nrouter+next].acl1), ri2(next, acl_link_list[from*nrouter+next].acl2);
    if (!isEmpty(ri)) tmp.insert(ri);
    if (!isEmpty(ri2)) tmp.insert(ri2);

    ri_path_map[tc] = tmp;
    return tmp;
  } 
  
  return ri_path_map[tc];
}

int main(int argc, char ** argv) {  

  //system("build/bin/wine SCAPPatt/SCAPP.exe ACL file=acltmp.txt permuation=any output=false verbose=true stats=temp.csv");

  //system("build/bin/wine SCAPPatt/SCAPP.exe ACL file=acltmp.txt permuation=any output=false verbose=true stats=temp.csv");

  //sleep(10);
  
  while (1) {
    char c = getopt(argc, argv, "n:r:b:s:");
    if (c == EOF) break;
    switch (c) {
    case 'n':
      if (strcmp(optarg, "cbb") == 0) network = NETWORK_CBB;
      else if (strcmp(optarg, "lightspeed") == 0) network = NETWORK_LIGHTSPEED;
      else if (strcmp(optarg, "usipfr") == 0) network  = NETWORK_USIPFR;
      else if (strcmp(optarg, "enterprise") == 0) network = NETWORK_ENTERPRISE;
      else if (strcmp(optarg, "campus") == 0) network = NETWORK_CAMPUS;
      else if (strcmp(optarg, "sbc") == 0) network = NETWORK_SBC;
      break;
    case 'r':
      if (strcmp(optarg, "network") == 0) runscheme = SCHEME_NETWORK;
      else if (strcmp(optarg, "oneswitch") ==0) runscheme = SCHEME_ONESWITCH;
      else if (strcmp(optarg, "binpack") == 0) runscheme = SCHEME_BINPACK;
      else if (strcmp(optarg, "partition") == 0) runscheme = SCHEME_PARTITION;
      else if (strcmp(optarg, "cache") == 0) runscheme = SCHEME_CACHE;
      break;
    case 'b':
      binsize = atoi(optarg);
      binsize = (unsigned long)exp10(binsize);
      break;
    case 's':
      //switchsize = atoi(optarg);
      //ncut = (int)pow(totalrules/switchsize, 1/6) +1;
      ncut = atoi(optarg);
      sprintf(tmpaclfile,"tmp%d.txt", ncut);
      sprintf(statsfile, "stats%d.txt", ncut);
      sprintf(csvfile, "temp%d.csv", ncut);
      break;
    default:
      printf("?? getopt returned character code 0%o ??\n",c);
      break;
    }
    
    
  }

  switch (network) {
  case NETWORK_CBB:
    strcpy(directory, "cbb-20090910");
    break;
  case NETWORK_LIGHTSPEED:
    strcpy(directory, "lightspeed-20090910");
    break;
  case NETWORK_USIPFR:
    strcpy(directory, "usipfr-20090910");
    break;
  case NETWORK_ENTERPRISE:
    strcpy(directory, "enterprise-20070428");
    break;
  case NETWORK_CAMPUS:
    strcpy(directory, "campus");
    break;
  case NETWORK_SBC:
    strcpy(directory, "sbc-20090910");
    break;
  }
  if (runscheme == SCHEME_NETWORK || runscheme == SCHEME_BINPACK) {
    sprintf(filename, "%s/interface.tbl", directory);
    read_interface(filename); 
    
    sprintf(filename, "%s/backbonelinks.tbl", directory);
    read_network(filename); 
  }
  if (runscheme == SCHEME_ONESWITCH || runscheme == SCHEME_NETWORK || runscheme == SCHEME_BINPACK || runscheme == SCHEME_CACHE) {
    switch (network) {
    case NETWORK_CBB:
      file_format = FORMAT_EXT;
      sprintf(filename, "%s/acl_ext_entries.tbl", directory);
      read_file(filename);
      file_format = FORMAT_STD;
      sprintf(filename, "%s/acl_std_entries.tbl", directory);
      read_file(filename);
      file_format = FORMAT_JUNOS;
      sprintf(filename, "%s/acl_junos_entries.tbl", directory);
      read_file(filename);
      file_format = FORMAT_XR;
      sprintf(filename, "%s/acl_xr_entries.tbl", directory);
      read_file(filename);
      break;
    case NETWORK_LIGHTSPEED:
      file_format = FORMAT_LIGHTSPEED;
      sprintf(filename, "%s/acl.tbl", directory);
      read_file(filename); 
      break;
    case NETWORK_USIPFR:
      file_format = FORMAT_EXT;
      sprintf(filename, "%s/acl_ext_entries.tbl", directory);
      read_file(filename);
      file_format = FORMAT_STD;
      sprintf(filename, "%s/acl_std_entries.tbl", directory);
      read_file(filename);
      break;
    case NETWORK_ENTERPRISE:
      file_format = FORMAT_EXT;
      sprintf(filename, "%s/acl_ext_entries.tbl", directory);
      read_file(filename);
      file_format = FORMAT_STD;
      sprintf(filename, "%s/acl_std_entries.tbl", directory);
      read_file(filename);      
      file_format = FORMAT_LIGHTSPEED;
      sprintf(filename, "%s/acl.tbl", directory);
      read_file(filename);      
      break;
    case NETWORK_CAMPUS:
      for (int i = 1; i < 1647; i ++) {
        sprintf(filename, "/n/fs/routre/large_campus_configs/configs/config%d", i);
        read_file_campus(filename, i-1);
      }
      nrouter = 1646;
      break;
    case NETWORK_SBC:
      file_format = FORMAT_EXT;
      sprintf(filename, "%s/pltn13.tbl", directory);
      cout << filename << endl;
      read_file(filename);
      sprintf(filename, "%s/pltnca.tbl", directory);
      read_file(filename);
      break;
    }
    
    //exit(0);

  ofstream fout("aclcount.txt");
  ofstream fout2("aclrulecount.txt");
  //ofstream fout3("routerrulecount.txt");

  int count = 0;
  //int output = 0;
  for (map<string, int>::iterator mi = routermap.begin(); mi != routermap.end(); mi ++) {
    fout << acl_per_router[mi->second].size() << endl;
    count = 0;
    for (set<int>::iterator si = acl_per_router[mi->second].begin(); si != acl_per_router[mi->second].end(); si ++) {
      router_interface_class ri(mi->second, *si);
      /*if (rule_group[ri].size() > 1000) {
        cout << ri << get_router(ri.router_id) << endl;
        output ++;
        if (output > 10)
          exit(0);
          }*/
      fout2 << rule_group[ri].size() << endl;
      count += rule_group[ri].size();
    }
    //fout3 << count << endl;
  }
  }

    if (runscheme == SCHEME_PARTITION) {
      file_format = FORMAT_EXT;      
      sprintf(filename, "cbb-20090910/new.acl");
      read_file(filename);
    }


    cout << " #rules " << nrule << " #routers " << nrouter << endl; 
    cout << "proto " << proto_count.size() << " sp " << sp_count.size() << " dp " << dp_count.size() << " sip " << sip_count.size() << " dip " << dip_count.size() << endl;


  cout << "=======finish reading files==========" << endl;

  policy_class defaultp;
  defaultp.router_id = 0;
  defaultp.acl_num = 0;
  defaultp.entry_index = 9999;
  defaultp.action = ACTION_DENY;
  defaultp.protocol = PROTO_IP;
  defaultp.src.addr = 0;
  defaultp.src.len  =0;
  defaultp.dst.addr = 0;
  defaultp.dst.len  =0;
  defaultp.sport.first = 0;
  defaultp.sport.last = MAX_PORT;
  defaultp.dport.first = 0;
  defaultp.dport.last = MAX_PORT;
  
  if (runscheme == SCHEME_BINPACK) {
    switch (network) {
    case NETWORK_CBB:
      tree_file_count = 24758927;
      break;
    case NETWORK_LIGHTSPEED:
      tree_file_count = 21139;
      break;
    case NETWORK_USIPFR:
      break;
    }
    
    //tree_file_count = 100;
    for (int i = 1; i <= tree_file_count; i ++) {
      //i  = 194;
      sprintf(filename, "indextrees-%s/acl%d.dat", directory, i);
      cout << filename << endl;
      ifstream ifs;
      ifs.open(filename, ios::in);
      if (!ifs.is_open()) {
        ifs.close();
        continue;
      }
      tree_node * newtree = new tree_node;
      int pair_count;
      char str[255];
      ifs.getline(str, MAX_STRING_LEN);
      sscanf(str, "%d", &pair_count);
      int result = newtree->read_file(ifs);      
      if (result < 0) {
        if (newtree) delete newtree;
        newtree = NULL;
      }
      
      if (newtree) {
        //cout << filename << endl;
        //ofstream ofs("tmp.dat");
        //newtree->write_file(ofs);
        //exit(0);
        //newtree->print();
      
        int ruletmp = newtree->count_rules();
        sprintf(filename, "%s-treeacl.txt", directory);
        fnetacl.open(filename, ios_base::app);
        for (int k = 0; k < pair_count; k ++) 
          fnetacl << ruletmp << endl;
        fnetacl.close();
        
        int count = newtree->add_treesize(binsize, pair_count);
        //cout << count << endl;
        if ((unsigned long)count < binsize) {
          treesize_class ti;
          ti.size = count;
          ti.count = pair_count;
          treesize.push_back(ti);
        }
        newtree->delete_tree();
      }
    }      
    count_bins(binsize);
  }

  if (runscheme == SCHEME_NETWORK) {

    ofstream ofinternal("ofinternal.txt");
    
    spath = new ShortestPath[nrouter*nrouter];
    sprintf(filename, "%s-spath.txt", directory);
    //calc_shortest_path(spath, nrouter, nlink, link_list); 
    //dump_spath(nrouter, filename, spath);
    get_spath(nrouter, filename, spath);
    cout << "=======finish shortest path==========" << endl;
    //exit(0);

    //tree_node * tmptmp = NULL;
    //add_interface(tmptmp, 667, 206);
    //exit(0);

    /*for (int i = 0; i < nrouter; i ++) {
      cout << " router " << i << endl;
      for (set<int>::iterator si = acl_per_router[i].begin(); si != acl_per_router[i].end(); si ++) {
        router_interface_class ri(i, *si);
        //10512
        cout << ri << endl;
        flush(cout);
        defaultp.router_id = i;
        defaultp.acl_num = *si;
        sort(rule_group[ri].begin(), rule_group[ri].end());
        tree_node * tmp;
        create_tree_for_router(tmp, rule_group[ri], defaultp);
        router_tree[ri] = tmp;
        //tmp->print();
        router_tree[ri]->merge_tree();
        //tmp->print();
      }
      }*/

    //cout << get_router(0) << " " << get_router(34) << endl;

    int flag, flag2;
    for (int i = 0; i < nrouter; i ++) {
      //cout << i << endl;
      //i = 1102;
      for (int j = 0; j < nrouter; j ++) {
        if (i == j) continue;
        if (spath[i*nrouter+j].next == -1) continue;
        flag = 0;
        //i = 0; j = 34; 
        cout << i << " " << j << endl;
        for (vector<interface_class>::iterator si = interface_set[i].begin(); si != interface_set[i].end(); si ++) {
          if (si->type == INTERFACE_INTERNAL) continue;
          router_interface_class ri(i, si->in_acl);
          if (si->in_acl < 0 || rule_group[ri].size() == 0) {
            if (flag) continue;
            flag = 1;
          }
          flag2 = 0;
          for (vector<interface_class>::iterator si2 = interface_set[j].begin(); si2 != interface_set[j].end(); si2++) {
            if (si2->type == INTERFACE_INTERNAL) continue;
            router_interface_class ri2(j, si2->out_acl);
            if (si2->out_acl < 0 || rule_group[ri2].size() == 0) {
              if (flag2) continue;
              flag2 = 1;
            }
             
            //cout << si->in_acl << " " << si2->out_acl << endl;

            //find all the shortest path ACLs
            set<router_interface_class> settmp;
            settmp = get_ri_on_path(i, j, si2->out_acl);
            if (!isEmpty(ri)) settmp.insert(ri);

            router_interface_class ri1 = ri;
            if (settmp.size() == 1) {
              if (si->in_acl >= 0 && rule_group[ri].size() > 0) {
                ri2.router_id = -1;
                ri2.acl_num = -1;
              } else {
                if (si2->out_acl >= 0 && rule_group[ri2].size() > 0) {
                  ri1.router_id = -1;
                  ri1.acl_num = -1;
                }
              }
            }               
            
            int internal = settmp.size();
            if (si->in_acl >= 0 && rule_group[ri].size() > 0) {
              incount ++;
              internal --;
            } 
            if (si2->out_acl >= 0 && rule_group[ri2].size() > 0) {
              outcount ++;
              internal --;
            }
            ofinternal << internal << endl;
            
            
            ripair_class rpair(ri1, ri2);
            rimap[settmp].insert(rpair);
          }
        }            
      }      
    }

    cout << "incount " << incount << endl;
    cout << "outcount " << outcount << endl;
    
    ofinternal.close();

    //exit(0);
    
    cout << "======= finish shortest path acl list ========" << endl;
    
    cout << " total " << rimap.size() << endl;

    tree_node * tmp = NULL;
    for (map<set<router_interface_class>, set<ripair_class> >::iterator mi = rimap.begin(); mi != rimap.end(); mi ++) {
      if (mi->second.size() == 0) continue;
      if (mi->first.size() == 0) continue;
      
      tree_file_count ++;
      cout << "acl group " << tree_file_count << endl;

      tmp = NULL;
      for (set<router_interface_class>::iterator si = mi->first.begin(); si != mi->first.end(); si ++) {
        //cout << *si << endl;
        add_interface(tmp, si->router_id, si->acl_num);
      }

      char filename[255];
      sprintf(filename, "indextrees-%s/acl%d.dat", directory, tree_file_count);
      ofstream ofs(filename);
      ofs << mi->second.size() << endl;
      tmp->write_file(ofs);
      ofs.close();
      tmp->delete_tree();
    }

    cout << "total trees " << tree_file_count << endl;

  }

  if (runscheme == SCHEME_ONESWITCH) {

    sprintf(filename, "%s-size.txt", directory);
    ofstream fsize(filename);
    
    int max = 0, max_i, max_si;
    
    for (int i = 0; i < nrouter; i ++) {
      //cout << " router " << i;
      for (set<int>::iterator si = acl_per_router[i].begin(); si != acl_per_router[i].end(); si ++) {
        router_interface_class ri(i, *si);
        defaultp.router_id = i;
        defaultp.acl_num = *si;
        //cout << rule_group[ri].size() << endl;
        sort(rule_group[ri].begin(), rule_group[ri].end());
        tree_node * tmp;
        
        //cout << ri << " " << endl;

        create_tree_for_router(tmp, rule_group[ri], defaultp);
        router_tree[ri] = tmp;

        int originalsize = 0;
        for (vector<policy_index_class>::iterator rulei = rule_group[ri].begin(); rulei != rule_group[ri].end(); rulei ++) {
          originalsize += policy_list[rulei->rule_id].sport.count_prefixes(TREE_TYPE_SPORT)
            * policy_list[rulei->rule_id].dport.count_prefixes(TREE_TYPE_DPORT);
        }

        //int beforerule = router_tree[ri]->count_rules();
         if (debug)
           cout << "start merge" << endl;
         router_tree[ri]->merge_tree();
        
         //tree_node * tmp2;
        //router_tree[ri]->copy_tree(tmp2);
        //int count = router_tree[ri]->count_duplicates();
        //int nleaves = router_tree[ri]->count_leaves();
        int nrules = router_tree[ri]->count_rules();
        
        if (rule_group[ri].size() == 0 ) {
          cout << "size error" << endl;
        } else {
          if (rule_group[ri].size() > (unsigned int)max) {
            max_i = i;
            max_si = *si;
          }
          fsize << rule_group[ri].size() << " " << nrules/(double)originalsize << endl;
        }

      }
    }

    cout << get_router(max_i) << " " << max_si << endl;

    fsize.close();
  }

  if (runscheme == SCHEME_PARTITION) {
    switchsize = (int) ((double)nrule/ncut * 1.3);
    //ncut = (int)(pow(ncut, 1/6)+2);
    
    cout << "switchsize " << switchsize << " ncut " << ncut << endl;

    hypercube root;
    root.set(0, 0, nrouter);
    root.set(1, 0, 4294967295);
    root.set(2, 0, 4294967295);
    root.set(3, 0, 65535);
    root.set(4, 0, 65535);
    root.set(5, 0, 255);
    int total_rules = partition(root, 0);
    cout << "totol rules " << total_rules << endl;
    
    /*ofstream ftmp("stats.txt");
    ftmp.close();
    
    for (int i = 0; i < nrouter; i ++) {
      for (set<int>::iterator si = acl_per_router[i].begin(); si != acl_per_router[i].end(); si ++) {
        ofstream  facltmp("acltmp.txt");
        facltmp << "! test" << endl;
        facltmp << "Proto,SIP,SP,DIP,DP" <<endl;
        facltmp << "0:255,0:4294967295,0:65535,0:4294967295,0:65535" << endl;

        router_interface_class ri(i, *si);
        defaultp.router_id = i;
        defaultp.acl_num = *si;
        sort(rule_group[ri].begin(), rule_group[ri].end());
      
        if (rule_group[ri].size() == 0 ) {
          cout << "size error" << endl;
        } else {
          for (vector<policy_index_class>::iterator vi = rule_group[ri].begin(); vi != rule_group[ri].end(); vi ++) {
            policy_list[vi->rule_id].output(facltmp);
          }
          defaultp.output(facltmp);
          facltmp.close();

          cout << i<< " " << *si << endl;
          system("build/bin/wine SCAPPatt/SCAPP.exe ACL file=acltmp.txt permuation=any output=false verbose=true stats=temp.csv");
          cout << "finish" << endl;
          system("tail -n 1 temp.csv >> stats.txt");

        }
      }
    }*/
  }  
  

  if (runscheme == SCHEME_CACHE) {
    
    double start_time = get_current_time();
  
    //sprintf(filename, "%s/udppart", directory);
    sprintf(filename, "%s/udppackets", directory);
    ifstream ifpkt(filename);
    ifpkt.getline(str, MAX_STRING_LEN);
    char str[255];

    long loss = 0;
    long total = 0;

    vector<cache_entry> cache;

    int ruletype = CACHE_WILD;
    int testtype = CACHE_SIZE;

    int cache_size = ncut;

    long count  = 0;
    
    while (ifpkt.getline(str, MAX_STRING_LEN)) {
      packet_class pkt;
      //cout << str << endl;
      if (count ==3 ) {
        cout << "wrong" << endl;
        }
      pkt.getpkt(str);      
      //cout << pkt.src << " " << pkt.dst << endl;
      total ++;

      count ++;
      cout << count << endl;
      if (count == 10000000) break;

      int hit = 0;
      for (vector<cache_entry>::iterator vi = cache.begin(); vi != cache.end(); vi ++) {
        if (vi->match(pkt)) {
          //cout << vi->src << " " << vi->dst << endl;
          hit = 1;
          vi->time = pkt.time;
          break;
        }
      }
      if (hit) continue;
      
      loss ++;

      hit = 0;
 
      cache_entry c;
      c.time = pkt.time;
  
      for (int i = 0; i < nrouter; i ++) {
        for (set<int>::iterator si = acl_per_router[i].begin(); si != acl_per_router[i].end(); si ++) {          
          router_interface_class ri(i, *si);
          if (rule_group[ri].size() == 0 ) {
            cout << "size error" << endl;
          } else {
            //cout << rule_group[ri].size() << endl;
            for (vector<policy_index_class>::iterator vi = rule_group[ri].begin(); vi != rule_group[ri].end(); vi ++) {
              if (policy_list[vi->rule_id].src.contains(pkt.src) && policy_list[vi->rule_id].dst.contains(pkt.dst)) {
                int rt;
                hit = 1; 
                if (ruletype == CACHE_WILD) {
                  range_class src, dst;
                  policy_list[vi->rule_id].src.getrange(src.first, src.last);
                  policy_list[vi->rule_id].dst.getrange(dst.first, dst.last);
                  //if (src.first == 0 && src.last ==4294967295 && dst.first == 0 && dst.last == 4294967295 ) {
                  //  hit = 0; 
                  //  break;
                  //}
                  for (vector<policy_index_class>::iterator vi2 = rule_group[ri].begin(); vi2 != vi; vi2 ++) {
                    range_class newsrc, newdst;
                    policy_list[vi2->rule_id].src.getrange(newsrc.first, newsrc.last);
                    policy_list[vi2->rule_id].dst.getrange(newdst.first, newdst.last);
                    rt = src.minus(newsrc, pkt.src);
                    if (rt < 0) break;
                    rt = dst.minus(newdst, pkt.dst);
                    if (rt < 0) break;
                  }
                  //cout << src << " " << " " << pkt.src << endl;
                  src.getprefix(c.src, pkt.src);
                  dst.getprefix(c.dst, pkt.dst);                  
                  //cout << c.src << " " << c.dst << endl;
                  
                }
                if (rt < 0) hit = 0;
                break;
              }
            }
          }  
          if (hit) break;
        }
        if (hit) break;
      }

      if (!hit) {
        total --; 
        loss --; 
        continue;
      }

      if (ruletype == CACHE_MICRO) {
        c.src = pkt.src;
        c.dst = pkt.dst;
      }

      cache.push_back(c);
      vector<cache_entry>::iterator dvi;
      if (testtype == CACHE_SIZE && cache.size() > (unsigned int)cache_size) {
        int mintime = 99999;
        for (vector<cache_entry>::iterator vi = cache.begin(); vi != cache.end(); vi ++) {
          if (vi->time < mintime) {
            mintime = vi->time;
            dvi = vi;
          }
        }         
        cache.erase(dvi);      
      }
      
      int tag = 1;
      while (tag) {
        tag = 0;
        for (vector<cache_entry>::iterator vi = cache.begin(); vi != cache.end(); vi ++) {
          if (vi->time < c.time - 50) {
            dvi = vi;
            tag = 1;
            break;
          }
        }         
        if (tag) cache.erase(dvi);        
      }

      
    }

    cout << loss << " " << total << endl;
    
    double end_time = get_current_time();
    printf(" cache start time %lf %lf", start_time, end_time);


}

}
