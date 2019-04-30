#Peter Jiang
#lab3controller.py
#cmpe150 
# Based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.
    #print "Example Code."
    #install table entry

    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    #show a few dump flow entries by setting idle and hard time out
    msg.idle_timeout = 4
    msg.hard_timeout = 5

    
    tcp = packet.find('tcp') #look for tcp  packets

    if tcp is None: #if not tcp
        print("not TCP")
        ip = packet.find('ipv4') #look for ip packet
        if ip is None:
          arp = packet.find('arp')
          if arp is not None:
            print("is ARP")
            msg.data = packet_in
            msg.match.dl_type = 0x0806 #arp
            action = of.ofp_action_output(port = of.OFPP_FLOOD)
            msg.actions.append(action)
            self.connection.send(msg)
          else:
            print("ARP dropped")
            msg.data = packet_in
            self.connection.send(msg)
        else:
          icmp = packet.find("icmp")
          if icmp is None:
              print("icmp dropped")
              msg.data = packet_in
              self.connection.send(msg)
          else:
              msg.data = packet_in
              msg.match.nw_proto = 1
              action = of.ofp_action_output(port = of.OFPP_ALL)
              msg.actions.append(action)
              self.connection.send(msg)
    
    else: #tcp
        ip = packet.find("ipv4")
        if ip is None:
            msg.data = packet_in
            self.connection.send(msg)
        else:
          if ip.srcip == ("10.0.1.30") and ip.dstip == ("10.0.1.10"):
            msg.data = packet_in
            msg.match.nw_proto = 6 #TCP
            action = of.ofp_action_output(port = of.OFPP_FLOOD)
            msg.actions.append(action)
            self.connection.send(msg)
            print("TCP packet sent!")
          elif ip.srcip == ("10.0.1.10") and ip.dstip == ("10.0.1.30"):
            msg.data = packet_in
            msg.match.nw_proto = 6 #TCP
            action = of.ofp_action_output(port = of.OFPP_FLOOD)
            msg.actions.append(action)
            self.connection.send(msg)
            print("TCP packet sent!")
          else:
            msg.data = packet_in
            self.connection.send(msg)
            print("TCP dropped")

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """


    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
