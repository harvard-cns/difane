#include "acl.hh"

ostream& operator<< (ostream &out, const range_class &p) {
  out << "[" << p.first << "," << p.last << "]";
  return out;
}

ostream& operator<< (ostream &out, const router_interface_class &p) {
  out << "[" << p.router_id << "," << p.acl_num << "]";
  return out;
}

string getType(int type) {
  switch (type) {
  case 0: 
    return "TYPE_NODE";
  case 1: 
    return "TYPE_LEAF";
  case 2: 
    return "TYPE_PROTO";
  case 3:
    return "TYPE_SRC";
  case 4:
    return "TYPE_DST";
  case 5:
    return "TYPE_SPORT";
  case 6:
    return "TYPE_DPORT";
  }
  return "";
}

int addinfo(tree_node * root, tree_node * newroot, 
            tree_node * curr, tree_node * newcurr, 
            range_class * range, range_class * newrange, 
            int step, int newstep) {
  if (!root || !newroot) return 0;
  if (!curr) return 0;
  
  if (curr && curr->type == TREE_TYPE_LEAF) {
    if (curr->action == ACTION_DENY) 
      return 0;

    if (!newcurr) return 0;

    if (newcurr && newcurr->type == TREE_TYPE_LEAF) {
      if (curr->action == ACTION_ACCEPT) 
        return 0;
      
      tree_node * roottmp = root;
      range_class r;
      for (int i = 0; i < step; i ++) {
        if (newrange[i].first > range[i].first && newrange[i].first <= range[i].last) {
          r.first = range[i].first;
          r.last = newrange[i].first - 1;
          roottmp->child[r]->copy_tree(roottmp->child[range[i]]);
          roottmp->range.push_back(r);
        }
        if (newrange[i].last >=range[i].first && newrange[i].last < range[i].last) {
          r.first = newrange[i].last + 1;
          r.last = range[i].last;
          roottmp->child[r]->copy_tree(roottmp->child[range[i]]);
          roottmp->range.push_back(r);
        }
        r.first = newrange[i].first;
        r.last = newrange[i].last;
        if (r.first < range[i].first) 
          r.first = range[i].first;
        if (r.last > range[i].last)
          r.last = range[i].last;
        roottmp->child[r] = roottmp->child[range[i]];
        roottmp->range.push_back(r);
        roottmp->range.remove(range[i]);
        if (roottmp->type == TREE_TYPE_LEAF)
          roottmp->action = ACTION_DENY;
        else roottmp = roottmp->child[r];
      }
    }

    for (list<range_class>::iterator vi = newcurr->range.begin(); vi != newcurr->range.end(); vi ++) {
      if (vi->first > range[newstep].last || vi->last < range[newstep].first) 
        continue;
      newrange[newstep+1] = *vi;
      addinfo(root, newroot, curr, newcurr->child[*vi], range, newrange, step, newstep+1);
    }
  }
  
  for (list<range_class>::iterator vi = curr->range.begin(); vi != curr->range.end(); vi ++) {
    range[step+1] = *vi;
    addinfo(root, newroot, curr->child[*vi], newcurr, range, newrange, step+1, 0);
  }
  
  return 0;
}
