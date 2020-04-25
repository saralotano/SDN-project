package net.floodlightcontroller.task2;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

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
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
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
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.util.FlowModUtils;

public class VirtualAddressController implements IOFMessageListener, IFloodlightModule {
	private Timer masterDownTimer;
	private TimerTask timerTask;
	protected IFloodlightProviderService floodlightProvider; // Reference to the provider

	class Election extends TimerTask {
		public void run() {
			System.out.println("A new election is started. A new Master is found: " + startElection());
		}
	}
	
	@Override
	public String getName() {
		return VirtualAddressController.class.getSimpleName();
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
		System.out.println("Virtual Address Controller is starting");
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
				System.out.println("The message can't be cast to Packet-In. Message type is: " + msg.getType());
				return Command.CONTINUE;
			}
			OFPacketIn pi = (OFPacketIn) msg;

	        // Dissect Packet included in Packet-In
			if (pkt instanceof IPv4) {
				IPv4 ip_pkt = (IPv4) pkt;
				if(ip_pkt.getProtocol().compareTo(IpProtocol.UDP) == 0) {
					UDP udp = (UDP) ip_pkt.getPayload();
					if(udp.getDestinationPort().compareTo(Utils.PORT_NUMBER) == 0) {
						// adv message from router
						System.out.println("[VAC] Processing ADV Message");
						handleAdvPacket(sw,pi,cntx);
					}
				} else {
					System.out.println("[VAC] ICMP message");
					handleIPPacket(sw, pi, cntx);
				}
				return Command.STOP;
			}
			// Continue the chain
			return Command.CONTINUE;
	}

	private void handleIPPacket(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {

		// Double check that the payload is IPv4
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (! (eth.getPayload() instanceof IPv4))
			return;
		
		// Cast the IP packet
		IPv4 ipv4 = (IPv4) eth.getPayload();
		
		// Check if the Master is still alive
		if(Utils.master == null) {
			System.out.println("The Virtual BR is offline");
			return;
		}
		
		//Controller can receive a Packet_In containing an ICMP packet in different cases:
		//	0) Ping request from host in Net A to host in Net B
		//	1) Ping reply from host in Net B to host in Net A
		//	2) Ping request from host in NetA to Virtual Router
		//  3) Ping reply from VR to host in NetA
		
		// Create a flow table modification message to add a rule
		OFFlowAdd.Builder fmb = sw.getOFFactory().buildFlowAdd();
		
        fmb.setIdleTimeout(Utils.ICMP_IDLE_TIMEOUT);
        fmb.setHardTimeout(Utils.ICMP_HARD_TIMEOUT);
        fmb.setBufferId(OFBufferId.NO_BUFFER);
        fmb.setCookie(U64.of(0));
        fmb.setPriority(FlowModUtils.PRIORITY_MAX);

        // Create the match structure  
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
        .setExact(MatchField.ETH_DST, Utils.VIRTUAL_MAC);
        
        OFActions actions = sw.getOFFactory().actions();
        // Create the actions (Change DST MAC and IP addresses and set the out-port)
        ArrayList<OFAction> actionListOut = new ArrayList<OFAction>();
        
        OFOxms oxms = sw.getOFFactory().oxms();
        
        // Packets directed to the virtual router (ping to 10.0.1.1) -> case 2)
        if(ipv4.getDestinationAddress().compareTo(Utils.VIRTUAL_IP) == 0) {
        	mb.setExact(MatchField.IPV4_DST, Utils.VIRTUAL_IP);
        	
        	OFActionSetField setIpDst = actions.buildSetField()
            	    .setField(
            	        oxms.buildIpv4Dst()
            	        .setValue(Utils.master.getIpAddress())
            	        .build()
            	    )
            	    .build();
            actionListOut.add(setIpDst);
        }
        
        OFActionSetField setEthDst = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthDst()
        	        .setValue(Utils.master.getMacAddress())
        	        .build()
        	    )
        	    .build();
        actionListOut.add(setEthDst);
        
        OFActionOutput output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(Utils.switchPorts.get(Utils.master.getMacAddress()))
        	    .build();
        actionListOut.add(output);
        
        fmb.setActions(actionListOut);
        fmb.setMatch(mb.build());

        sw.write(fmb.build());
        
     	// Set the rules for IPv4 packets directed to NetA
        
		// Create a flow table modification message to add a rule
		OFFlowAdd.Builder fmbRev = sw.getOFFactory().buildFlowAdd();
		
		fmbRev.setIdleTimeout(Utils.ICMP_IDLE_TIMEOUT);
		fmbRev.setHardTimeout(Utils.ICMP_HARD_TIMEOUT);
		fmbRev.setBufferId(OFBufferId.NO_BUFFER);
		fmbRev.setCookie(U64.of(0));
		fmbRev.setPriority(FlowModUtils.PRIORITY_MAX);
      
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(pi.getBufferId());
		pob.setInPort(OFPort.ANY);
		
		// Packet might be buffered in the switch or encapsulated in Packet-In 
		// If the packet is encapsulated in Packet-In sent it back
		if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
			// Packet-In buffer-id is none, the packet is encapsulated -> send it back
            byte[] packetData = pi.getData();
            pob.setData(packetData);            
		} 
		
		// Actions and matches for packets coming from Routers to netA
		
		ArrayList<OFAction> actionListIn = new ArrayList<OFAction>();
		Match.Builder mbIn = sw.getOFFactory().buildMatch();
		
		OFActionSetField setEthSrcIn = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthSrc()
        	        .setValue(Utils.VIRTUAL_MAC)
        	        .build()
        	    )
        	    .build();
        actionListIn.add(setEthSrcIn);
                
		// Reverse Rule if the Packet_In received is a ping From an host in NetA -> Packet_in: Case 0),2)
		if(eth.getDestinationMACAddress().compareTo(Utils.VIRTUAL_MAC) == 0) {
	        
	        mbIn.setExact(MatchField.ETH_TYPE, EthType.IPv4)
	        .setExact(MatchField.ETH_DST, eth.getSourceMACAddress());
	        // Ping directed to the Virtual Router -> Packet_In: Case 2)
	        if(ipv4.getDestinationAddress().compareTo(Utils.VIRTUAL_IP) == 0 ) {
	        	
	        	//Add to the match structure the Master's IP address as source in case of the ping reply
	        	mbIn.setExact(MatchField.IPV4_SRC, Utils.master.getIpAddress());
	        	
	        	//Hide the real IP of the master in ping reply from the router
	        	OFActionSetField setIpSrc = actions.buildSetField()
	            	    .setField(
	            	        oxms.buildIpv4Src()
	            	        .setValue(Utils.VIRTUAL_IP)
	            	        .build()
	            	    )
	            	    .build();
	            actionListIn.add(setIpSrc);
	        }
	        
	        OFActionOutput outputIn = actions.buildOutput()
	        	    .setMaxLen(0xFFffFFff)
	        	    .setPort(pi.getMatch().get(MatchField.IN_PORT))
	        	    .build();
	        actionListIn.add(outputIn);
	        
	        // Assign the actionList for the packets addressed to the Virtual MAC (outgoing from netA)
	        // Packet_In: Case 0),2)
	        pob.setActions(actionListOut);
	        
		} else {
			// Packet_In: Case 1),3)			
			mbIn.setExact(MatchField.ETH_TYPE, EthType.IPv4)
	        .setExact(MatchField.ETH_DST, eth.getDestinationMACAddress() ); //match the dest host and save the output port
	        
			// Packet_In : Case 3)
			if(ipv4.getSourceAddress().compareTo(Utils.master.getIpAddress()) == 0) {
	        	
	        	mbIn.setExact(MatchField.IPV4_SRC, Utils.master.getIpAddress());
	        	
	        	OFActionSetField setIpSrc = actions.buildSetField()
	            	    .setField(
	            	        oxms.buildIpv4Src()
	            	        .setValue(Utils.VIRTUAL_IP)
	            	        .build()
	            	    )
	            	    .build();
	            actionListIn.add(setIpSrc);
	        }
			
			// Check if the destination host's port is known, else flood the packet
			if(Utils.switchPorts.get(eth.getDestinationMACAddress()) != null) {
		        OFActionOutput outputRev = actions.buildOutput()
		        	    .setMaxLen(0xFFffFFff)
		        	    .setPort(Utils.switchPorts.get(eth.getDestinationMACAddress()))
		        	    .build();
		        actionListIn.add(outputRev);
			} else {
				OFActionOutput outputRev = actions.buildOutput()
		        	    .setMaxLen(0xFFffFFff)
		        	    .setPort(OFPort.FLOOD)
		        	    .build();
				actionListIn.add(outputRev);
			}
	        
	        // Assign the action for the incoming packets from the routers
			// Packet_In: Case 1),3)
			pob.setActions(actionListIn);
		}
	  
        fmbRev.setActions(actionListIn);
        fmbRev.setMatch(mbIn.build());
        
        //send the second FlowMode packet
        sw.write(fmbRev.build());
	
        //send the packet_out
		sw.write(pob.build());				
	}

	private void handleAdvPacket(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof IPv4))
			return;
		// Cast the IP packet
		IPv4 ipv4 = (IPv4) eth.getPayload();
		// Double check that the protocol is UDP
		if(ipv4.getProtocol().compareTo(IpProtocol.UDP) == 0) {
			UDP udp = (UDP) ipv4.getPayload();
			Data payload = (Data) udp.getPayload();
			String data = new String(payload.getData());
			String[] adv = data.split(":");
			if(adv.length != 2) {
				System.out.println("There is an error in the adv message format");
				return;
			}
			int priority;
			try {
				priority = Integer.parseInt(adv[1]);
			} catch(NumberFormatException ex) {
				System.out.println("the priority sent from the router can't be cast to an integer");
				return;
			}
			
			Router router = new Router(adv[0],ipv4.getSourceAddress(), eth.getSourceMACAddress(), priority, new Date().getTime());
			Utils.switchPorts.putIfAbsent(eth.getSourceMACAddress(), pi.getMatch().get(MatchField.IN_PORT));
			
			// Master is null when no router is registered or all routers are down
			if(Utils.master == null) {
				System.out.println("A new master is elected: "+adv[0]);
				Utils.master = router;
				// Set the timer
				setTimer();
			}
			else {
				// A new adv from current master is arrived
				if(Utils.master.getMacAddress().compareTo(router.getMacAddress()) == 0) {
					// Reset the timer
					resetTimer();
				} else if(Utils.master.getPriority() < router.getPriority()) { // Router with better priority is found
					Utils.master = router;
					System.out.println("A new master is elected: "+adv[0]);
					// Reset the timer
					resetTimer();
				}
			}
			Utils.routers.put(router.getMacAddress(), router);
		}
	}
	
	// A new master is elected among the active registered routers, choosing the one with the highest priority
	private String startElection() {
		if(Utils.master != null) {
			Utils.master.setPriority(-1);
			for(Map.Entry<MacAddress, Router> entry:Utils.routers.entrySet()) {
				if((new Date().getTime() - entry.getValue().getTimestamp()) < Utils.masterDownInterval && 
						entry.getValue().getPriority() > Utils.master.getPriority())
					Utils.master = entry.getValue();
			}
			// New master is found
			if(Utils.master.getPriority() != -1) {
				resetTimer();
				return Utils.master.getName();
			}
			// No active routers are found
			Utils.master = null;
		}
		return "None";
	}
	
	private void setTimer() {
		masterDownTimer = new Timer();
		timerTask = new Election();
		masterDownTimer.schedule(timerTask, Utils.masterDownInterval);
	}
	
	private void resetTimer() {
		masterDownTimer.cancel();
		masterDownTimer.purge();
		setTimer();
	}
	
}