# Peter Jinag
# CMPE150
#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController

class final_topo(Topo):
  def build(self):

    # Examples!
    # Create a host with a default route of the ethernet interface. You'll need to set the
    # default gateway like this for every host you make on this assignment to make sure all
    # packets are sent out that port. Make sure to change the h# in the defaultRoute area
    # and the MAC address when you add more hosts!
    h10 = self.addHost('h1',mac='00:00:00:00:00:01',ip='10.0.1.10/24', defaultRoute="h1-eth0")
    h20 = self.addHost('h2',mac='00:00:00:00:00:02',ip='10.0.2.20/24', defaultRoute="h2-eth0")
    h30 = self.addHost('h3',mac='00:00:00:00:00:03',ip='10.0.3.30/24', defaultRoute="h3-eth0")
    trust = self.addHost('h4',mac='00:00:00:00:00:04',ip='104.82.214.112/24', defaultRoute="h4-eth0")
    untrust = self.addHost('h5',mac='00:00:00:00:00:05',ip='156.134.2.12/24', defaultRoute="h5-eth0")
    server = self.addHost('h6', mac='00:00:00:00:00:05',ip='10.0.4.10/24', defaultRoute="h6-eth0")

    # Create a switch. No changes here from Lab 1.

    s1 = self.addSwitch('s1')  # Floor switch 1
    s2 = self.addSwitch('s2')  # Floor switch 2
    s3 = self.addSwitch('s3')  # Floor switch 3
    s4 = self.addSwitch('s4')  # Core switch
    s5 = self.addSwitch('s5')  # Data Center Switch

    #add links between switches. sw2-sw5 can be the same port, sw1 must be different
    self.addLink(s1,s4, port1=1, port2=1)
    self.addLink(s2,s4, port1=1, port2=2)
    self.addLink(s3,s4, port1=1, port2=3)
    self.addLink(s5,s4, port1=1, port2=4)

    # Connect Port 8 on the Switch to Port 0 on Host 1 and Port 9 on the Switch to Port 0 on
    # Host 2. This is representing the physical port on the switch or host that you are
    # connecting to.
    self.addLink(s1,h10, port1=8, port2=0)
    self.addLink(s2,h20, port1=9, port2=0)
    self.addLink(s3,h30, port1=8, port2=0)
    self.addLink(s4,trust, port1=8, port2=0)
    self.addLink(s4,untrust, port1=9, port2=0)
    self.addLink(s5,server, port1=8, port2=0 )

def configure():
  topo = final_topo()
  net = Mininet(topo=topo, controller=RemoteController)
  net.start()

  CLI(net)

  net.stop()


if __name__ == '__main__':
  configure()
