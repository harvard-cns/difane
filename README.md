This is a prelimnary version of DIFANE release, which
contains two parts:

1. Read wildcard rules and partition them. (partition directory)
NOTE: In the evaluation of our DIFANE paper, we used a tool
SCAPPATT to reduce the redundancy in the rules before
running the partition algorithm. The SCAPPATT tool was got
from Chad R. Meiners at meinersc@cse.msu.edu

2. DIFANE implementation in Click-based OpenFlow (You have
   to manually take 1.'s output rules into the authority
   switches you select.)
- The instructions for using Click-based OpenFlow is at
   http://www.openflowswitch.org/wk/index.php/OpenFlowClick
- Then you need to use our code (in prototype directory) to
   replace the openflow directory in Click

We are still working on integrating Part 1's function in
NOX, and combining Part 1 and Part 2 together
to build a complete DIFANE system.