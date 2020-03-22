package net.floodlightcontroller.task2;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.projectfloodlight.openflow.types.MacAddress;
import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.restserver.RestletRoutable;

public class RestController implements IFloodlightModule, IRestController {
		
	protected IRestApiService restApiService; // Reference to the Rest API service	

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IRestController.class);
	    return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
	    m.put(IRestController.class, this);
	    return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		// Add among the dependences the RestApi service
	    l.add(IRestApiService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// Retrieve a pointer to the rest api service
		restApiService = context.getServiceImpl(IRestApiService.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		System.out.println("Rest Controller is starting");
		// Add as REST interface the one defined in the RestControllerWebRoutable class
		restApiService.addRestletRoutable(new RestControllerWebRoutable());

	}

	/*
	 * Class to define the rest interface 
	 */
	
	public class RestControllerWebRoutable implements RestletRoutable {
	    /**
	     * Create the Restlet router and bind to the proper resources.
	     */
	    @Override
	    public Restlet getRestlet(Context context) {
	        Router router = new Router(context);
	        
	        // Add get network info
	        router.attach("/network/info/json", GetNetworkInfo.class);
	        // Add change numAdv variable
	        router.attach("/network/numadv/json", ChangeNumAdv.class);
	        return router;
	    }
	 
	    /**
	     * Set the base path for the Topology
	     */
	    @Override
	    public String basePath() {
	        return "/vr";
	    }
	}
	
	@Override
	public Map<String, Object> getNetworkInfo(){
		Map<String, Object> info = new HashMap<String, Object>();
		Map<String, RouterInfo> routers = new HashMap<String, RouterInfo>();
		// initialize routers with the registered ones
		for(MacAddress mac: Utils.routers.keySet()) {
			net.floodlightcontroller.task2.Router r = Utils.routers.get(mac);
			routers.put(r.getName(), new RouterInfo(r.getIpAddress().toString(),r.getMacAddress().toString(),r.getPriority()));
		}
		info.put("The registered routers are", routers);

		if(Utils.master != null)
			info.put("The Master is", Utils.master.getName());
		else 
			info.put("The Master is", "None");
		info.put("The numAdv is", Utils.numAdv);
		info.put("The advertisement Interval is (s)", Utils.advertisementInterval/1000);
		info.put("The master down interval is (s)", Utils.masterDownInterval/1000);
		info.put("The ICMP Idle Timeout is", Utils.ICMP_IDLE_TIMEOUT);
		info.put("The ICMP Hard Timeout is", Utils.ICMP_HARD_TIMEOUT);
		info.put("The ARP Idle Timeout is", Utils.ARP_IDLE_TIMEOUT);
		info.put("The ARP Hard Timeout is", Utils.ARP_HARD_TIMEOUT);
		return info;
	} 
	
	@Override
	public void setNumAdv(int newValue){
		if(newValue <= 0)
			return;
		Utils.numAdv = (short) newValue;
		System.out.println("Number Advertisement value changed to " + newValue);		
	}
	
	private class RouterInfo {
		private String ipAddress;
		private String macAddress;
		private int priority;
		
		public RouterInfo(String ipAddress, String macAddress, int priority) {
			this.ipAddress = ipAddress;
			this.macAddress = macAddress;
			this.priority = priority;
		}
		
		public String getIpAddress() {
			return ipAddress;
		}
		
		public String getMacAddress() {
			return macAddress;
		}
		
		public int getPriority() {
			return priority;
		}
	}

}
