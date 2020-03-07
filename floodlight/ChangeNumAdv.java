package net.floodlightcontroller.task2;

import java.io.IOException;

import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ChangeNumAdv extends ServerResource{
	@Post("json")
	public String store(String fmJson) {
		System.out.println("POST");
        // Check if the payload is provided
        if(fmJson == null){
            return new String("No attributes");
        }
		
		// Parse the JSON input
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode root = mapper.readTree(fmJson);
			
			//Check if the name field is correct
			if(root.get("numadv") == null)
				return new String("Wrong Format.The name has to be 'numadv'");
			// Get the field num_adv
			int newValue = Integer.parseInt(root.get("numadv").asText());
			IRestController rc = (IRestController) getContext().getAttributes().get(IRestController.class.getCanonicalName());
			
			rc.setNumAdv(newValue);
		
		}catch(NumberFormatException e) {
			e.printStackTrace();
		}catch (IOException e) {
			e.printStackTrace();
		}
		
	    return new String("OK");

	}
}
