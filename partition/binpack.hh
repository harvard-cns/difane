#ifndef BINPACK_HH
#define BINPACK_HH

int count_bins(unsigned long binsize);

class treesize_class {
public:
  int count;
  unsigned long size;
    treesize_class() {
    count = 0;
    size = 0;
  }
    treesize_class(int a, unsigned long l): count(a), size(l) { }
    treesize_class(const treesize_class& p) {
      count=p.count;
      size=p.size;
    }
    void set(int a, int l) {
      count=a; size=l;
    }
    treesize_class& operator=(const treesize_class& p) {
      count=p.count;
      size=p.size;
      return *this;
    }
    bool operator==(const treesize_class& p) const {
      if (count ==p.count  && size==p.size) {
        return true;
      }
      else {
        return false;
      }
    }
    bool operator!=(const treesize_class& p) const {
      if (count ==p.count  && size==p.size) {
        return false;
      }
      else {
        return true;
      }
    }
    bool operator<(const treesize_class& p) const {
      if (size<p.size) {
        return true;
      }
      else if (size==p.size) {
        return (count <p.count);
      }
      else {
        return false;
      }
    }

  
};

#endif
