package net.floodlightcontroller.task2;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

public class Router {
	private IPv4Address ipAddress;
	private MacAddress macAddress;
	private int priority;
	private long timestamp;
	
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
	
	public int getPriority() {
		return priority;
	}
	
	public long getTimestamp() {
		return timestamp;
	}
	
	public void setPriority(int priority) {
		this.priority = priority;
	}
	
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}
	
}
