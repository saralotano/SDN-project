package net.floodlightcontroller.task2;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.util.FlowModUtils;

public class ARPController implements IOFMessageListener, IFloodlightModule {
	
	protected IFloodlightProviderService floodlightProvider; // Reference to the provider

	@Override
	public String getName() {
		return ARPController.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		System.out.println("ARP Controller is starting");
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {
			
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			
			IPacket pkt = eth.getPayload();
			
			// Cast to Packet-In
			if(msg.getType().compareTo(OFType.PACKET_IN) != 0) {
				System.out.println("The message can't be cast to Packet-In. Mesasge type is: " + msg.getType());
				return Command.CONTINUE;
			}
			OFPacketIn pi = (OFPacketIn) msg;

	        // Dissect Packet included in Packet-In
			if (pkt instanceof ARP) {
				// Cast the ARP request
				ARP arpMessage = (ARP) eth.getPayload();
				Utils.switchPorts.putIfAbsent(eth.getSourceMACAddress(), pi.getMatch().get(MatchField.IN_PORT));
				
				System.out.println("[ARP] Target address: "+arpMessage.getTargetProtocolAddress());
				System.out.println("[ARP] Sender address: "+arpMessage.getSenderProtocolAddress());
				
				// Process ARP request for Virtual Router
				if(arpMessage.getTargetProtocolAddress().compareTo(Utils.VIRTUAL_IP) == 0) {
					System.out.println("[ARP] Processing ARP request for VR");
					handleARPRequestForVR(sw, pi, cntx);
					return Command.STOP;
				} else if(Utils.routers.containsKey(arpMessage.getSenderHardwareAddress())){
					
					// Process ARP request from Virtual Router
					System.out.println("[ARP]Processing ARP request from Routers");
					handleARPRequestFromVR(sw, pi, cntx);
					return Command.STOP;
				}
			}
			// Continue the chain
			return Command.CONTINUE;

	}
	
	private void handleARPRequestForVR(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {

		// Double check that the payload is ARP
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof ARP))
			return;
		
		// Cast the ARP request
		ARP arpRequest = (ARP) eth.getPayload();
		
		// Generate ARP reply
		IPacket arpReply = new Ethernet()
			.setSourceMACAddress(Utils.VIRTUAL_MAC)
			.setDestinationMACAddress(eth.getSourceMACAddress())
			.setEtherType(EthType.ARP)
			.setPriorityCode(eth.getPriorityCode())
			.setPayload(
				new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setHardwareAddressLength((byte) 6)
				.setProtocolAddressLength((byte) 4)
				.setOpCode(ARP.OP_REPLY)
				.setSenderHardwareAddress(Utils.VIRTUAL_MAC) // Set my MAC address
				.setSenderProtocolAddress(Utils.VIRTUAL_IP) // Set my IP address
				.setTargetHardwareAddress(arpRequest.getSenderHardwareAddress())
				.setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));
		
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(OFPort.ANY);
		
		// Create action -> send the packet back from the source port
		OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
		// The method to retrieve the InPort depends on the protocol version 
		OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);
		actionBuilder.setPort(inPort); 
		
		// Assign the action
		pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		
		// Set the ARP reply as packet data 
		byte[] packetData = arpReply.serialize();
		pob.setData(packetData);
				
		sw.write(pob.build());
		
	}

	private void handleARPRequestFromVR(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {
		// Double check that the payload is ARP
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof ARP))
			return;
		
		// Cast the ARP request
		ARP arpRequest = (ARP) eth.getPayload();
		
		// Create a flow table modification message to add a rule
		OFFlowAdd.Builder fmb = sw.getOFFactory().buildFlowAdd();
		
        fmb.setIdleTimeout(Utils.ARP_IDLE_TIMEOUT);
        fmb.setHardTimeout(Utils.ARP_HARD_TIMEOUT);
        fmb.setBufferId(OFBufferId.NO_BUFFER);
        fmb.setOutPort(OFPort.ANY);
        fmb.setCookie(U64.of(0));
        fmb.setPriority(FlowModUtils.PRIORITY_MAX); 

        // Create the match structure  
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_TYPE, EthType.ARP)
        .setExact(MatchField.ETH_SRC, eth.getSourceMACAddress());
        
        OFActions actions = sw.getOFFactory().actions();
        // Create the actions (Change SRC MAC and IP addresses and set the out-port)
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        
        OFOxms oxms = sw.getOFFactory().oxms();
        
        OFActionSetField setEthSrc = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthSrc()
        	        .setValue(Utils.VIRTUAL_MAC)
        	        .build()
        	    )
        	    .build();
        actionList.add(setEthSrc);
        
        OFActionSetField setArpSHA = actions.buildSetField()
        	    .setField(
        	        oxms.buildArpSha()
        	        .setValue(Utils.VIRTUAL_MAC)
        	        .build()
        	    )
        	    .build();
        actionList.add(setArpSHA);

        OFActionSetField setArpSPA = actions.buildSetField()
        	    .setField(
        	        oxms.buildArpSpa()
        	        .setValue(Utils.VIRTUAL_IP)
        	        .build()
        	    ).build();
        actionList.add(setArpSPA);
        
        OFActionOutput output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(OFPort.FLOOD)
        	    .build();
        actionList.add(output);
        
        
        fmb.setActions(actionList);
        fmb.setMatch(mb.build());

        sw.write(fmb.build());
      
        
        // Reverse Rule to change the destination MAC and IP addresses and mask the action of the controller
        
		// Create a flow table modification message to add a rule
		OFFlowAdd.Builder fmbRev = sw.getOFFactory().buildFlowAdd();
		
		fmbRev.setIdleTimeout(Utils.ARP_IDLE_TIMEOUT);
		fmbRev.setHardTimeout(Utils.ARP_HARD_TIMEOUT);
		fmbRev.setBufferId(OFBufferId.NO_BUFFER);
		fmbRev.setOutPort(OFPort.CONTROLLER);
		fmbRev.setCookie(U64.of(0));
		fmbRev.setPriority(FlowModUtils.PRIORITY_MAX);

        Match.Builder mbRev = sw.getOFFactory().buildMatch();
        mbRev.setExact(MatchField.ETH_TYPE, EthType.ARP)
        .setExact(MatchField.ETH_DST, Utils.VIRTUAL_MAC);
        
        ArrayList<OFAction> actionListRev = new ArrayList<OFAction>();
        
        OFActionSetField setEthDstRev = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthDst()
        	        .setValue(arpRequest.getSenderHardwareAddress())
        	        .build()
        	    )
        	    .build();
        actionListRev.add(setEthDstRev);
        
        OFActionSetField setArpThaRev = actions.buildSetField()
        	    .setField(
        	        oxms.buildArpTha()
        	        .setValue(arpRequest.getSenderHardwareAddress())
        	        .build()
        	    )
        	    .build();
        actionListRev.add(setArpThaRev);

        OFActionSetField setArpTpaRev = actions.buildSetField()
        	    .setField(
        	        oxms.buildArpTpa()
        	        .setValue(arpRequest.getSenderProtocolAddress())
        	        .build()
        	    ).build();
        actionListRev.add(setArpTpaRev);

        OFActionOutput outputRev = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(pi.getMatch().get(MatchField.IN_PORT))
        	    .build();
        actionListRev.add(outputRev);
        
        fmbRev.setActions(actionListRev);
        fmbRev.setMatch(mbRev.build());
        
        sw.write(fmbRev.build());
        
        // If we do not apply the same action to the packet we have received and we send it back the first packet will be lost
        // Create the Packet-Out and set basic data for it (buffer id and in port)
 		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
 		pob.setBufferId(pi.getBufferId());
 		pob.setInPort(OFPort.ANY);
 		
        // Assign the action
 		pob.setActions(actionList);
 		
 		// Packet might be buffered in the switch or encapsulated in Packet-In 
 		// If the packet is encapsulated in Packet-In sent it back
 		if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
 			// Packet-In buffer-id is none, the packet is encapsulated -> send it back
 			byte[] packetData = pi.getData();
 			pob.setData(packetData);
             
 		} 
 				
 		sw.write(pob.build());
        		
	}
	
}