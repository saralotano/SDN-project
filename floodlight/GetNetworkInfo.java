package net.floodlightcontroller.task2;

import java.util.Map;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class GetNetworkInfo extends ServerResource{
	@Get("json")
	public Map<String,Object> Test() {
		IRestController rc = (IRestController) getContext().getAttributes().get(IRestController.class.getCanonicalName());
    	return rc.getNetworkInfo();
	}
}
