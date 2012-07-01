#include <sys/time.h>
#include "util.h"

uint32_t str2ip(const char * str) {
  int a, b, c, d;
  sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
  return  (uint32_t)(a*(exp2(24)) + b*(exp2(16)) + c*(exp2(8)) + d);
}

char * ip2str(uint32_t ip) {
  struct in_addr tmp; 
  tmp.s_addr=ntohl(ip);
  return inet_ntoa(tmp); 
}

void calc_shortest_path(ShortestPath * spath, int n, int m, Link * link) {
  int i,j,k;

  for (i = 0; i < n; i ++) {
    for (j = 0; j < n; j ++) {
      if (i == j) {
        (*(spath+i*n+j)).length = 0;
        (*(spath+i*n+j)).next = i;
      } else {
        (*(spath+i*n+j)).length = MAX_DOUBLE; // does this look like infinity ?
        (*(spath+i*n+j)).next = -1;
      }
    }
  }
  for (k=0; k<m; k++) {
    if (link[k].from == -1 && link[k].to == -1) continue;
    i = link[k].from;
    j = link[k].to;
    (*(spath+i*n+j)).length = link[k].weight;
    (*(spath+i*n+j)).next = j;
    //(*(spath+j*n+i)).length = link[k].weight;
    //(*(spath+j*n+i)).next = i;
  }

  for (k=0; k<n; k++)
    {
      for (i=0; i<n; i++)
        {
          for (j=0; j<n; j++)
            {
              if ( (*(spath+i*n+k)).length + (*(spath+k*n+j)).length < (*(spath+i*n+j)).length)
                {
                  // A[i][j] = A[i][k] + A[k][j];
                  (*(spath+i*n+j)).length = (*(spath+i*n+k)).length+ (*(spath+k*n+j)).length;
                  (*(spath+i*n+j)).next = (*(spath+i*n+k)).next;
                }
            }
        }
    }

} // Floyd's algorithm

double get_current_time() {
  struct timeval time;                                                                                                                                     
  gettimeofday(&time, NULL);                                                                                                                                 
  return (double)time.tv_sec + (double)time.tv_usec/(double)1000000;
}
 
void dump_spath(int nrouter, char * filename, ShortestPath * spath) {
  ofstream fspath(filename);
  int i, j;
  for (i = 0; i < nrouter; i ++) {
    for (j = 0; j < nrouter; j ++) {
      fspath << (int)spath[i*nrouter+j].length << " " << (int)spath[i*nrouter+j].next << endl;
    }
  }
}

void get_spath(int nrouter, char * filename, ShortestPath * spath) {
  ifstream fspath(filename);
  int i, j;
  char str[255];
  int length, next;
  for (i = 0;i < nrouter; i ++) 
    for (j = 0; j < nrouter; j ++) {
      fspath.getline(str, MAX_STRING_LEN);
      sscanf(str, "%d %d", &length, &next);
      spath[i*nrouter+j].length = length;
      spath[i*nrouter+j].next = next;
    }
}
