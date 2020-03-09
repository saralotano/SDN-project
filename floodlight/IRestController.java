package net.floodlightcontroller.task2;

import java.util.Map;

import net.floodlightcontroller.core.module.IFloodlightService;

//Service interface for the module
//This interface will be use to interact with other modules
//Export here all the methods of the class that are likely used by other modules

public interface IRestController extends IFloodlightService {
	// Methods exposed by the module
	
	// Method to retrieve the parameters saved in the controller
	public Map<String,Object> getNetworkInfo();
	// Method to set the number of advertisement lost before considering the Master Down
	public void setNumAdv(int newValue);
}
