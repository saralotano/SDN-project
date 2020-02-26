package net.floodlightcontroller.task2;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TransportPort;

public class Utils {
	// IP and MAC address for our logical load balancer
	protected final static IPv4Address VIRTUAL_IP = IPv4Address.of("10.0.1.1");
	protected final static MacAddress VIRTUAL_MAC = MacAddress.of("00:00:5E:00:01:01");
	protected final static TransportPort PORT_NUMBER = TransportPort.of(1234);
	protected static HashMap<MacAddress,Integer> switchPorts = new HashMap<MacAddress,Integer>();	// da cambiare 
	protected static HashMap<MacAddress,Integer> clients = new HashMap<MacAddress,Integer>();
	// List of registered routers ordered by priority
	//protected static List<Router> routers = new ArrayList<Router>();
	protected static HashMap<MacAddress, Router> routers= new HashMap<MacAddress,Router>();
	protected static Router master;
	// Time expected for the advertisements
	protected static int advertisementInterval = 1000;	// in milliseconds (1 sec)
	private static int numAdv = 3;
	private static int nextNumPort = 1;
	// Time after that the router is considered down
	protected static int masterDownInterval = numAdv * advertisementInterval;	// in milliseconds
	// Rule timeouts
	protected final static short IDLE_TIMEOUT = 10; // in seconds
	protected final static short HARD_TIMEOUT = (short) (masterDownInterval / 1000);	// in seconds
	
	/*
	protected static boolean checkMaster() {
		if(master != null) {
			// Check if the master is still alive
			if((new Date().getTime() - master.getTimestamp()) <= masterDownInterval)
				return true;
			else {	// a new Master has to be chosen
				master.setPriority(-1);
				for(Map.Entry<MacAddress, Router> entry:routers.entrySet()) {
					if((new Date().getTime() - entry.getValue().getTimestamp()) <= masterDownInterval && 
							entry.getValue().getPriority() > master.getPriority())
						master = entry.getValue();
				}
				if(master.getPriority() != -1)
					return true;
				// no active routers are found
				master = null;
			}
		}
		return false;
	}
	*/
	
	protected static void insertClient(MacAddress mac) {
		if(clients.putIfAbsent(mac, nextNumPort) == null)
			nextNumPort ++;
	}
	
	protected static void insertSwitchPort(MacAddress mac) {
		if(switchPorts.putIfAbsent(mac, nextNumPort) == null)
			nextNumPort ++;
	}
}