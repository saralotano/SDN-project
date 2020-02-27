package net.floodlightcontroller.task2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMatchBmap;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.util.HexString;
import org.python.constantine.platform.darwin.IPProto;

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
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;

public class ARPController implements IOFMessageListener, IFloodlightModule {
	
	protected IFloodlightProviderService floodlightProvider; // Reference to the provider

	@Override
	public String getName() {
		return ARPController.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
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
		// TODO Auto-generated method stub
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
				System.out.println("Target address: "+arpMessage.getTargetProtocolAddress());
				System.out.println("Sender address: "+arpMessage.getSenderProtocolAddress());
				if(eth.isBroadcast() || eth.isMulticast()) {	// ARP request
					//System.out.println("[ARP] in port is:" + pi.getMatch().get(MatchField.IN_PORT));
					// Process ARP request for Virtual Router
					if(arpMessage.getTargetProtocolAddress().compareTo(Utils.VIRTUAL_IP) == 0) {
						System.out.println("Processing ARP request for VR");
						handleARPRequestForVR(sw, pi, cntx);
					} else if(arpMessage.getSenderProtocolAddress().compareTo(Utils.master.getIpAddress()) == 0){
						// Process ARP request from Virtual Router
						System.out.println("Processing ARP request from VR");
						handleARPRequestFromVR(sw, pi, cntx);
					}
				} else {	// ARP reply
					if(arpMessage.getTargetProtocolAddress().compareTo(Utils.VIRTUAL_IP) == 0) {
						System.out.println("Processing ARP reply to VR");
						handleARPReplyToVR(sw, pi, cntx);
					}
				}
				// Stop the chaine
				return Command.STOP;
			}
			// Interrupt the chain
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
		
		//System.out.printf("Sending out ARP reply\n");
		
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
		/*
		eth.setSourceMACAddress(Utils.VIRTUAL_MAC);
		arpRequest.setSenderHardwareAddress(Utils.VIRTUAL_MAC);
		arpRequest.setSenderProtocolAddress(Utils.VIRTUAL_IP);
		eth.setPayload(arpRequest);
		*/
		
		System.out.println("Destination Mac Address is Broadcast? "+eth.getDestinationMACAddress());
		System.out.println("Unknown Targer Mac? "+arpRequest.getTargetHardwareAddress());
		IPacket newArpRequest = new Ethernet()
			.setSourceMACAddress(Utils.VIRTUAL_MAC)
			.setDestinationMACAddress(eth.getDestinationMACAddress())	// Broadcast?
			.setEtherType(EthType.ARP)
			.setPriorityCode(eth.getPriorityCode())
			.setPayload(
				new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setHardwareAddressLength((byte) 6)
				.setProtocolAddressLength((byte) 4)
				.setOpCode(ARP.OP_REQUEST)
				.setSenderHardwareAddress(Utils.VIRTUAL_MAC) // Set my MAC address
				.setSenderProtocolAddress(Utils.VIRTUAL_IP) // Set my IP address
				.setTargetHardwareAddress(arpRequest.getTargetHardwareAddress())	// Unknown?
				.setTargetProtocolAddress(arpRequest.getTargetProtocolAddress()));
		
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(OFPort.ANY);
		
		// Send the packet to all the ports except the one from which it receives the ARP req
		OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
		// The method to retrieve the InPort depends on the protocol version 
		
		//OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);
		//actionBuilder.setPort(inPort); 
		
		actionBuilder.setPort(OFPort.FLOOD); 

		// Assign the action
		pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		
		// Set the ARP reply as packet data 
		byte[] packetData = newArpRequest.serialize();
		pob.setData(packetData);
		sw.write(pob.build());
	}
	
	private void handleARPReplyToVR(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {

		// Double check that the payload is ARP
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof ARP))
			return;
		
		// Cast the ARP request
		ARP arpReply = (ARP) eth.getPayload();
		eth.setDestinationMACAddress(Utils.master.getMacAddress());
		arpReply.setTargetHardwareAddress(Utils.master.getMacAddress());
		arpReply.setTargetProtocolAddress(Utils.master.getIpAddress());
		eth.setPayload(arpReply);
		/*
		// Generate ARP reply
		IPacket arpReply = new Ethernet()
			.setSourceMACAddress(Utils.VIRTUAL_MAC)
			.setDestinationMACAddress(eth.getDestinationMACAddress()) // Dovrebbe essere quello broadcast
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
		*/
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(OFPort.ANY);
		
		// Send the packet to all the ports except the one from which it receives the ARP req
		OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
		// The method to retrieve the InPort depends on the protocol version 
		//OFPort inPort = OFPort.ANY;
		actionBuilder.setPort(Utils.switchPorts.get(Utils.master.getMacAddress())); 
		
		// Assign the action
		pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		
		// Set the ARP reply as packet data 
		byte[] packetData = eth.serialize();
		pob.setData(packetData);
		
		sw.write(pob.build());
	}
	
}