#include "util.h"
#include "binpack.hh"

class treesize_class;

vector<treesize_class> treesize;


int main(int argc, char ** argv) {
  char filename[100];
  int binsize;

  strcpy(filename, "balls.txt");

  treesize_class tc;
  
  while (1) {
    char c = getopt(argc, argv, "f:s:");
    if (c == EOF) break;
    switch (c) {
    case 'f':
      strcpy(filename, optarg);
      break;
    case 's':
      binsize = (int)(atof(optarg)*1000);
      break;
    default:
      printf("?? getopt returned character code 0%o ??\n",c);
      break;
    }
  }

  ifstream fin(filename);
  
  int ntree, nbin;
  //map<int, set<int> > bin;
  
  int size;

  while (fin >> size) {
    if (size > 0) {
      tc.size = size;
      tc.count = 1;
      treesize.push_back(tc);
      ntree ++;
    }
  }

  nbin = count_bins(binsize);
  cout << nbin << endl;
}

