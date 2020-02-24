package net.floodlightcontroller.task2;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

public class Router {
	protected IPv4Address ipAddress;
	protected MacAddress macAddress;
	protected int priority;
	protected long timestamp;
	
	public Router(IPv4Address ipAddress, MacAddress macAddress, int priority, long timestamp) {
		this.ipAddress = ipAddress;
		this.macAddress = macAddress;
		this.priority = priority;
		this.timestamp = timestamp;
	}
	
	public IPv4Address getIpAddress() {
		return ipAddress;
	}
	
	public MacAddress getMacAddress() {
		return macAddress;
	}
	
	public long getTimestamp() {
		return timestamp;
	}
	
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}
	
}
