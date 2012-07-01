#include "cube.hh"
#include "util.h"
#include "policy.hh"
#include "acl.hh"

extern int nrouter;
extern map<router_interface_class, vector<policy_index_class> > rule_group;
extern set<int> acl_per_router[MAX_ROUTER];

extern int switchsize;
extern int ncut;

extern char tmpaclfile[100];
extern char statsfile[100];
extern char csvfile[100];


map<range_class, int> rule_number[10];


ostream& operator<< (ostream &out, const hypercube &p) {
  out << p.protocol.first << ":" << p.protocol.last <<","
       <<p.src.first << ":" << p.src.last << ","
       << p.sport.first << ":" << p.sport.last << ","
       << p.dst.first << ":" << p.dst.last << ","
       << p.dport.first <<":"<< p.dport.last;
  return out;
}

int intersect(range_class & r1, range_class & r2) {
  if ((uint64_t)r1.first > (uint64_t)r2.last || (uint64_t)r1.last < (uint64_t)r2.first) return 0;
  if ((uint64_t)r1.first < (uint64_t)r2.first) r1.first = r2.first;
  if ((uint64_t)r1.last > (uint64_t)r2.last) r1.last = r2.last;
  return 1;
}

int policy2file(ofstream & facltmp, hypercube cube, range_class divide, policy_class ptmp, int max_index) {

  //cout << cube << endl;
            range_class r1;
            r1.first = ptmp.protocol;
            r1.last = ptmp.protocol;
            if (r1.first == 255) r1.first = 0;
            int rt;
            if (max_index == 5) {
                rt = intersect(r1, divide); 
            } else {
              rt = intersect(r1, cube.protocol);
            }
            if (!rt) return -1;
           
            range_class r2;
            ptmp.src.getrange(r2.first, r2.last);
            if (max_index == 1) {
                rt = intersect(r2, divide); 
            } else {
              rt = intersect(r2, cube.src);
            }
            if (!rt) return -1;

            range_class r3;
            r3.first  = ptmp.sport.first;
            r3.last  = ptmp.sport.last;
            if (max_index == 3) {
                rt = intersect(r3, divide); 
            } else {
              rt = intersect(r3, cube.sport);
            }
            if (!rt) return -1;

            range_class r4;
            ptmp.dst.getrange(r4.first, r4.last);
            if (max_index == 2) {
                rt = intersect(r4, divide); 
            } else {
              rt = intersect(r4, cube.dst);
            }
            if (!rt) return -1;

            range_class r5;
            r5.first  = ptmp.dport.first;
            r5.last  = ptmp.dport.last;
            if (max_index == 4) {
                rt = intersect(r5, divide); 
            } else {
              rt = intersect(r5, cube.dport);
            }
            if (!rt) return -1;
          

            facltmp << r1.first <<":"<< r1.last << "," ;
            facltmp << r2.first <<":"<< r2.last << "," ;
            facltmp << r3.first <<":"<< r3.last << "," ;
            facltmp << r4.first <<":"<< r4.last << "," ;
            facltmp << r5.first <<":"<< r5.last << "," ;

   
            facltmp << (int)ptmp.action << endl;

            return 0;
}

int get_count() {
    int orig, after1, after2, sum = 0;
    char cmd[255];
    char str[255];
    sprintf(cmd, "rm -f %s", tmpaclfile);
    system(cmd);
    sprintf(cmd, "cat %s | awk -F, '{print $7, $5, $9}' > %s", statsfile, tmpaclfile);
    system(cmd);
    //sleep(1);
    ifstream fp(tmpaclfile);
    if (!fp) 
      cout << statsfile << " " << tmpaclfile << endl;
    while (fp.getline(str, MAX_STRING_LEN)) {
      sscanf(str, "%d %d %d", &orig, &after1, &after2);
      if (after2 < after1) after1 = after2;

      sum += after1;
    }
    fp.close();

    return sum;
}

int partition(hypercube cube, int step) {
  set<uint32_t> countset[10];
  policy_class defaultp;

  countset[0].insert(cube.router.first);
  countset[0].insert(cube.router.last);
  countset[1].insert(cube.src.first);
  countset[1].insert(cube.src.last);
  countset[2].insert(cube.dst.first);
  countset[2].insert(cube.dst.last);
  countset[3].insert(cube.sport.first);
  countset[3].insert(cube.sport.last);
  countset[4].insert(cube.dport.first);
  countset[4].insert(cube.dport.last);
  countset[5].insert(cube.protocol.first);
  countset[5].insert(cube.protocol.last);

  ofstream oftmp(statsfile);
  oftmp.close();


  int count = 0;
  for (int i = 0; i < nrouter; i ++) {
    if (cube.router.contain(i)) {
      countset[0].insert(i);
      for (set<int>::iterator si = acl_per_router[i].begin(); si != acl_per_router[i].end(); si ++) {   
        router_interface_class ri(i, *si);

        count ++;
        //cout << count << endl;
        //cout << ri << endl;
        //cout << rule_group[ri].size();


        ofstream facltmp(tmpaclfile);
        facltmp << "! test" << endl;
        facltmp << "Proto,SIP,SP,DIP,DP" <<endl;
        facltmp << "0:255,0:4294967295,0:65535,0:4294967295,0:65535" << endl;
    
        //count unique values in dimensions
        if (rule_group[ri].size() == 0 ) {
          cout << "size error" << endl;
        } else {
          for (vector<policy_index_class>::iterator vi = rule_group[ri].begin(); vi != rule_group[ri].end(); vi ++) {
            policy_class ptmp = policy_list[vi->rule_id];
            range_class r;

            //cout << cube << endl;

            //cout << ptmp << endl;
            policy2file(facltmp, cube, r, ptmp, -1);
            
            ptmp.src.getrange(r.first, r.last);
            if (cube.src.contain(r.first)) countset[1].insert(r.first);
            if (cube.src.contain(r.last)) countset[1].insert(r.last);
            ptmp.dst.getrange(r.first, r.last);
            if (cube.dst.contain(r.first)) countset[2].insert(r.first);
            if (cube.dst.contain(r.last)) countset[2].insert(r.last);
            if (cube.sport.contain(ptmp.sport.first)) countset[3].insert(ptmp.sport.first);
            if (cube.sport.contain(ptmp.sport.last)) countset[3].insert(ptmp.sport.last);
            if (cube.dport.contain(ptmp.dport.first)) countset[4].insert(ptmp.dport.first);
            if (cube.dport.contain(ptmp.dport.last)) countset[4].insert(ptmp.dport.last);
            if (cube.protocol.contain(ptmp.protocol))
              countset[5].insert(ptmp.protocol);
            if (ptmp.protocol == 255 && cube.protocol.contain(0)) countset[5].insert(0);
          } 
        }

        facltmp << cube << "," << (int)ACTION_DENY << endl;
        facltmp.close();
        if (step > 0) {
          char cmd[255];
          sprintf(cmd, "build/bin/wine SCAPPatt/SCAPP.exe ACL file=%s permuation=any output=false verbose=true stats=%s > /dev/null 2>/dev/null", tmpaclfile, csvfile);
          system(cmd);
          sprintf(cmd, "tail -n 1 %s >> %s", csvfile, statsfile);
          system(cmd);
        }
        
      }       
    }
  }

  int cuberules = nrule;
  if (step > 0) {
    cuberules = get_count();
    return cuberules;
  }

  if (cuberules <=switchsize) return cuberules;
  cout << "step " << step << " " << cuberules << endl;
  
  int max = 0, max_index = -1;
  for (int i = 0; i < 5; i ++) {
    if (countset[i].size() > (unsigned int)max) {
      max = countset[i].size();
      max_index = i;
    }
  }

  cout << max << " " << max_index << endl;
  vector<int> binlist;

  int totalsize = 0;

  ifstream fp("tmpsize");

  uint32_t tend;
  
  set<uint32_t>::iterator si2 = countset[max_index].begin();
  for (set<uint32_t>::iterator si = countset[max_index].begin(); si != countset[max_index].end(); si ++) {
    uint32_t start = *si +1;
    si2 ++;
    if (si2 == countset[max_index].end()) {
      tend = *si;
      break;
    }
    uint32_t end = *si2;
    range_class divide;
    divide.first = start;
    divide.last = end;
    if (si == countset[max_index].begin()) start --;

    cout << *si << " " << *si2;

    ofstream oftmp(statsfile);
    oftmp.close();

    if (step > 0) {
    for (int i = 0; i < nrouter; i ++) {
      if (!cube.router.contain(i)) continue;
      if (max_index == 0 && start > (uint32_t)i || (uint32_t)i > end) continue; 
      
      for (set<int>::iterator si = acl_per_router[i].begin(); si != acl_per_router[i].end(); si ++) {   
        router_interface_class ri(i, *si);
    
        range_class r;
        hypercube newcube = cube;
        newcube.get(max_index, r.first, r.last);
        intersect(r, divide);
        newcube.set(max_index, r.first, r.last);

        if (rule_number[max_index].find(r) == rule_number[max_index].end()) {
        ofstream  facltmp(tmpaclfile);
        facltmp << "! test" << endl;
        facltmp << "Proto,SIP,SP,DIP,DP" <<endl;
        facltmp << cube << endl;

        if (rule_group[ri].size() == 0 ) {
          cout << "size error" << endl;
        } else {
          for (vector<policy_index_class>::iterator vi = rule_group[ri].begin(); vi != rule_group[ri].end(); vi ++) {
            policy_class ptmp = policy_list[vi->rule_id];

            int rt = policy2file(facltmp, newcube, divide, ptmp, max_index);
            if (rt < 0) continue;
         } 
        }

        facltmp << newcube << "," << (int)ACTION_DENY << endl;
        facltmp.close();
          char cmd[255];
          sprintf(cmd, "build/bin/wine SCAPPatt/SCAPP.exe ACL file=%s permuation=any output=false verbose=true stats=%s > /dev/null 2>/dev/null", tmpaclfile, csvfile);
          system(cmd);
          sprintf(cmd, "tail -n 1 %s >> %s", csvfile, statsfile);
          system(cmd);
        } else {
          int rv = rule_number[max_index][r];
          binlist.push_back(rv);
          totalsize += rv;
        }
        
      }       

    }

    int rv = get_count();
    cout << " " << rv << endl;
    binlist.push_back(rv);
    totalsize += rv;
    }

    else {
      int tmp;
      range_class r;
      char str[100];
      fp.getline(str, MAX_STRING_LEN);
      // cout << str << endl;
      sscanf(str, "%d %d %d", &r.first, &r.last, &tmp);
      //cout << tmp << endl;

      binlist.push_back(tmp);

      rule_number[max_index][r] = tmp;

      totalsize += tmp;
    }
    
  }

  fp.close();

  cout << "count finish" << endl;
  
  //ncut, size
  hypercube newcube = cube;
  //newcube.get(max_index, r.first, r.last);
  //intersect(r, divide);
  //newcube.set(max_index, r.first, r.last);
  int sum = 0;
  //ncut = 2;
  int cutsize = totalsize/ncut;
  //int cutsize = switchsize* 10;

  //if (cutsize < switchsize) cutsize = switchsize;
  set<uint32_t>::iterator si  = countset[max_index].begin();
  set<uint32_t>::iterator si3  = countset[max_index].begin();
  si3 ++;
  uint32_t start = *si;
  int rules = 0;
  /*  for (vector<int>::iterator vi = binlist.begin(); vi != binlist.end(); vi ++) {
    si ++;
    si3 ++;
    if (sum + *vi > cutsize || si3 == countset[max_index].end()) {
      sum = 0;
      if (start == 0) {
        newcube.set(max_index, start, *si);
      } else 
        newcube.set(max_index, start + 1, *si);
      cout << step << ": partition " << *si << endl;
      int rt = partition(newcube, step+1);
      rules += rt;
      cout << step << ": " << newcube << " " << rt << endl;
      start = *si;
      }
    sum += *vi;
    } */
  
  for (int i = 0; i < ncut; i ++) {
    start = i*(tend/ncut) + 1;
    if (i == 0) start --;
    uint32_t end = (i+1) * (tend/ncut);
    if (i == ncut -1) end = tend;
        newcube.set(max_index, start , end);
        cout << step << ": partition " << start << " " << end << endl;
      int rt = partition(newcube, step+1);
      rules += rt;
      cout << step << ": " << newcube << " " << rt << endl;
    
  }
  
  return rules;

}

