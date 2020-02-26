#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class LinuxRouter( Node ):
	"A Node with priority and IP forwarding enabled."

	def __init__( self, name, prio, **params ):
		self.priority = prio
		Node.__init__( self, name, **params )

	def config( self, **params ):
		super( LinuxRouter, self).config( **params )
		# Enable forwarding
		self.cmd('sysctl net.ipv4.ip_forward=1') 
		self.cmd( 'python3 router.py '+self.name + ' ' + str(self.priority) + '&')

	def terminate( self ):
		self.cmd('sysctl net.ipv4.ip_forward=0')
		super( LinuxRouter, self ).terminate()


def buildNetworkTopology():
	net = Mininet(controller=RemoteController)
	c0 = net.addController('C0', controller=RemoteController, ip="127.0.0.1", port=6653)

    # Adding routers
	r1 = net.addHost('R1', cls=LinuxRouter, prio=255, ip='10.0.1.2/24')
	r2 = net.addHost('R2', cls=LinuxRouter, prio=100, ip='10.0.1.3/24')

	# Adding hosts
	h1 = net.addHost('H1', ip='10.0.1.4/24', defaultRoute='via 10.0.1.1')
	h2 = net.addHost('H2', ip='10.0.1.5/24', defaultRoute='via 10.0.1.1')
	h3 = net.addHost('H3', ip='10.0.1.6/24', defaultRoute='via 10.0.1.1')
	h4 = net.addHost('H4', ip='10.0.2.3/24', defaultRoute='via 10.0.2.1')
	h5 = net.addHost('H5', ip='10.0.2.4/24', defaultRoute='via 10.0.2.1')

	# Adding SDN-enabled switch
	s1 = net.addSwitch('S1')

	# Adding Legacy switch
	s2 = net.addSwitch('S2')

	# Adding links between network components
	net.addLink(s1, r1, intfName2='R1-eth0', params2={'ip' : '10.0.1.2/24'})
	net.addLink(s1, r2, intfName2='R2-eth0', params2={'ip' : '10.0.1.3/24'})
	net.addLink(h1, s1)
	net.addLink(h2, s1)
	net.addLink(h3, s1)		
	net.addLink(s2, r1, intfName2='R1-eth1', params2={'ip' : '10.0.2.1/24'})
	net.addLink(s2, r2, intfName2='R2-eth1', params2={'ip' : '10.0.2.2/24'})
	net.addLink(h4, s2)
	net.addLink(h5, s2)

	# Starting controller
	c0.start()

	# Adding controller only to switch S1
	s1.start([c0])
	s2.start([])

	net.start()
	CLI( net )
	net.stop()


if __name__ == '__main__':
	setLogLevel( 'info' )
	buildNetworkTopology()