package net.floodlightcontroller.task2;

import java.util.HashMap;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;

public class Utils {
	// IP and MAC address for our virtual router
	protected final static IPv4Address VIRTUAL_IP = IPv4Address.of("10.0.1.1");
	protected final static MacAddress VIRTUAL_MAC = MacAddress.of("00:00:5E:00:01:01");
	// Socket port for the communication between Controller and routers
	protected final static TransportPort PORT_NUMBER = TransportPort.of(1234);
	// Switch physical ports
	protected static HashMap<MacAddress,OFPort> switchPorts = new HashMap<MacAddress,OFPort>();
	// Registered routers
	protected static HashMap<MacAddress, Router> routers= new HashMap<MacAddress,Router>();
	protected static Router master;
	// Time expected for the advertisements
	protected static int advertisementInterval = 1000;	// in milliseconds (1 sec)
	protected static int numAdv = 3;
	// Time after that the router is considered down
	protected static int masterDownInterval = numAdv * advertisementInterval;	// in milliseconds
	// Rule's timeouts
	protected final static short ICMP_IDLE_TIMEOUT = (short) (masterDownInterval / 1000 / 2); // in seconds
	protected final static short ICMP_HARD_TIMEOUT = (short) (masterDownInterval / 1000);	// in seconds
	protected final static short ARP_IDLE_TIMEOUT = 10;
	protected final static short ARP_HARD_TIMEOUT = 20;
	
}