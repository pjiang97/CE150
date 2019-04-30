# Peter Jiang
# CE150
# Hints/Reminders from Lab 4:
#
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
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

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # This is where you'll put your code. The following modifications have
    # been made from Lab 4:
    #   - port_on_switch represents the port that the packet was received on.
    #   - switch_id represents the id of the switch that received the packet
    #      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)

    msg = of.ofp_flow_mod()
    x = of.ofp_flow_mod()

    ip = packet.find('ipv4')
    port = 0

    #check for ip packet
    if ip is not None:
      print("ip packet")
      msg.match = of.ofp_match.from_packet(packet)
      #For host 1, use switch 1
      if switch_id == 1:
        if ip.dstip == "10.0.1.10":
          if ip.srcip == "156.134.2.12":
              #check for icmp from untrusted host
              icmp = packet.find("icmp")
              if icmp:
                #drop packet
                msg.data = packet_in
                self.connection.send(msg)
                print("ip from untrusted host dropped")
          else:
            port = 8
            msg.actions.append(of.ofp_action_output(port = port))
            msg.data = packet_in
            self.connection.send(msg)
        else:
          #send to switch4, core switch
          print("sending to swtich 4 from switch1")
          port = 1
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = packet_in
          self.connection.send(msg)
      #For host2, switch 2
      elif switch_id == 2:
        if ip.dstip == "10.0.2.20":
          if ip.srcip == "156.134.2.12":
              #check icmp packet for untrusted host
              icmp = packet.find("icmp")
              if icmp:
                msg.data = packet_in
                self.connection.send(msg)
                print("ip from untrusted host dropped")

              else:
                port = 9
                msg.actions.append(of.ofp_action_output(port = port))
                msg.data = packet_in
                self.connection.send(msg)

          else:
            port = 9
            msg.actions.append(of.ofp_action_output(port = port))
            msg.data = packet_in
            self.connection.send(msg)
        else:

          print("sending to switch from s2")
          port = 1
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = packet_in
          self.connection.send(msg)

      elif switch_id == 3:
        if ip.dstip == "10.0.3.30":
          if ip.srcip == "156.134.2.12":
              icmp = packet.find("icmp")
              if icmp:
                msg.data = packet_in
                self.connection.send(msg)
                print("ip from untrusted host dropped")
          else:
            port = 8
            msg.actions.append(of.ofp_action_output(port = port))
            msg.data = packet_in
            self.connection.send(msg)
        else:
          print("sending to switch from s3")
          port = 1
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = packet_in
          self.connection.send(msg)

      #server
      elif switch_id == 5:
        if ip.dstip == "10.0.4.10":
          if ip.srcip == "156.134.2.12":
              print("ip from untrusted host dropped")
              msg.data = packet_in
              self.connection.send(msg)
          else:
            port = 8
            msg.actions.append(of.ofp_action_output(port = port))
            msg.data = packet_in
            self.connection.send(msg)
        else:
          print("sending to switch from s5")
          port = 1
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = packet_in
          self.connection.send(msg)
      #send to appropriate switch
      elif switch_id == 4:
        if ip.dstip == "10.0.1.10":
          print("sent to switch 1")
          port = 1
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = packet_in
          self.connection.send(msg)
        elif ip.dstip=="10.0.2.20":
          print("sent to switch 2")
          port = 2
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = packet_in
          self.connection.send(msg)
        elif ip.dstip=="10.0.3.30":
          print("sent to switch 3")
          port = 3
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = packet_in
          self.connection.send(msg)
        elif ip.dstip=="10.0.4.10":
          print("sent to switch 5")
          port = 4
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = packet_in
          self.connection.send(msg)
        elif ip.dstip == "104.82.214.112":
          print("sent to trusted host")
          port = 8
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = packet_in
          self.connection.send(msg)
        elif ip.dstip == "156.134.2.12":
          port = 9
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = packet_in
          self.connection.send(msg)
        else:
          print("failed")
          return
    else:
          x.match = of.ofp_match.from_packet(packet)
          x.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
          x.data = packet_in
          self.connection.send(x)


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
