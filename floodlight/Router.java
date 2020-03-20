package net.floodlightcontroller.task2;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

//Router information

public class Router {
	private String name;
	private IPv4Address ipAddress;
	private MacAddress macAddress;
	private int priority;
	private long timestamp;
	
	public Router(String name, IPv4Address ipAddress, MacAddress macAddress, int priority, long timestamp) {
		this.name = name;
		this.ipAddress = ipAddress;
		this.macAddress = macAddress;
		this.priority = priority;
		this.timestamp = timestamp;
	}
	
	public String getName() {
		return name;
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