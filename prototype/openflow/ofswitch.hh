#ifndef OFSWITCH_HH
#define OFSWITCH_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <click/confparse.hh>
#include "openflow_genl.hh"

CLICK_DECLS

/*
 * =c
 * Ofswitch()
 * =s debugging
 * demonstrates how to write a package
 * =d
 *
 * This is the only element in the `sample' package. It demonstrates how to
 * write an element that will be placed in a package. It does nothing except
 * report that the package was successfully loaded when it initializes. */

#define CHAIN_PURGE_FREQUENCY 1000
#define MAX_PORT_NAMES 10

class Ofswitch : public Element { 
public:
  Timer _timer;
  String port_name[MAX_PORT_NAMES];
  Datapath *dp0;
  
public:
  
  Ofswitch();	
  ~Ofswitch();

  const char *class_name() const	{ return "Ofswitch"; }
  int configure(Vector<String>&, ErrorHandler*);
  
  int initialize(ErrorHandler *errh);
  void cleanup(CleanupStage stage);
  void run_timer(Timer *timer);
  const char *port_count() const {  return "1-/="; }
  const char *processing() const {  return PUSH; }
  void push(int port, Packet *p_in);

};

CLICK_ENDDECLS
#endif
