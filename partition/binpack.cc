#include "util.h"
#include "binpack.hh"

class treesize_class;

extern vector<treesize_class> treesize;

int count_bins(unsigned long binsize) {
  sort(treesize.rbegin(), treesize.rend());
  //first fit decreasing algorithm for bin packing
  unsigned long i;
  int nbin = 0, j;
  map<int, unsigned long> bin;
  bin[0] = 0;
  
  cout << "binsize " << binsize << endl;

  for (i = 0; i < treesize.size(); i ++) {
    //cout << i << endl;
    //cout << treesize[i].size << " " << treesize[i].count << endl;
    for (int k = 0; k < treesize[i].count; k ++) {
      j = 0;
      while (bin[j] + treesize[i].size > binsize) {
        j ++;
        if (j > nbin) 
          bin[j] = 0;
      }
      if (bin[j] + treesize[i].size <= binsize) {
        bin[j] += treesize[i].size;
      } 
      if (j > nbin) {
        nbin = j;
      }
    }
  }
 
  cout << "ntree " << treesize.size() << " nbin " << nbin << endl;
  return nbin;
  //exit(0);
}

