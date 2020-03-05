package net.floodlightcontroller.task2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentSkipListSet;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMatchBmap;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetDlDst;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.util.HexString;
import org.python.constantine.platform.darwin.IPProto;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
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
			System.out.println("A new election is started. A new Masetr is found: " + startElection());
		}
	}
	
	@Override
	public String getName() {
		return VirtualAddressController.class.getSimpleName();
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
				System.out.println("The message can't be cast to Packet-In. Mesasge type is: " + msg.getType());
				return Command.CONTINUE;
			}
			OFPacketIn pi = (OFPacketIn) msg;

	        // Dissect Packet included in Packet-In
			if (pkt instanceof IPv4) {
				
				//System.out.printf("Processing IPv4 packet\n");
				
				IPv4 ip_pkt = (IPv4) pkt;
				
				if(ip_pkt.getProtocol().compareTo(IpProtocol.UDP) == 0) {
					UDP udp = (UDP) ip_pkt.getPayload();
					if(udp.getDestinationPort().compareTo(Utils.PORT_NUMBER) == 0) {
						handleAdvPacket(sw,pi,cntx);
					}
				} else 
					// Non ne sono sicura
					handleIPPacket(sw, pi, cntx);
					
				// Interrupt the chain
				return Command.STOP;
			}
			
			// Interrupt the chain
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
		
		// Create a flow table modification message to add a rule
		OFFlowAdd.Builder fmb = sw.getOFFactory().buildFlowAdd();
		
        fmb.setIdleTimeout(Utils.ICMP_IDLE_TIMEOUT);
        fmb.setHardTimeout(Utils.ICMP_HARD_TIMEOUT);
        fmb.setBufferId(OFBufferId.NO_BUFFER);
        fmb.setOutPort(OFPort.ANY);
        fmb.setCookie(U64.of(0));
        fmb.setPriority(FlowModUtils.PRIORITY_MAX);

        // Create the match structure  
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
        .setExact(MatchField.IPV4_DST, ipv4.getDestinationAddress())
        .setExact(MatchField.ETH_DST, Utils.VIRTUAL_MAC);
        
        OFActions actions = sw.getOFFactory().actions();
        // Create the actions (Change DST mac and IP addresses and set the out-port)
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        
        OFOxms oxms = sw.getOFFactory().oxms();
        
        OFActionSetField setDlDst = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthDst()
        	        .setValue(MacAddress.of(Utils.master.getMacAddress().getBytes()))
        	        .build()
        	    )
        	    .build();
        actionList.add(setDlDst);

        OFActionSetField setNwDst = actions.buildSetField()
        	    .setField(
        	        oxms.buildIpv4Dst()
        	        .setValue(ipv4.getDestinationAddress())
        	        .build()
        	    ).build();
        actionList.add(setNwDst);
        
        //System.out.println("[VA]Physical output port numeber is: "+Utils.switchPorts.get(Utils.master.getMacAddress()));
        OFActionOutput output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(Utils.switchPorts.get(Utils.master.getMacAddress()))
        	    .build();
        actionList.add(output);
        
        
        fmb.setActions(actionList);
        fmb.setMatch(mb.build());

        sw.write(fmb.build());
        
        // Reverse Rule to change the source address and mask the action of the controller
        
		// Create a flow table modification message to add a rule
		OFFlowAdd.Builder fmbRev = sw.getOFFactory().buildFlowAdd();
		
		fmbRev.setIdleTimeout(Utils.ICMP_IDLE_TIMEOUT);
		fmbRev.setHardTimeout(Utils.ICMP_HARD_TIMEOUT);
		fmbRev.setBufferId(OFBufferId.NO_BUFFER);
		fmbRev.setOutPort(OFPort.CONTROLLER);
		fmbRev.setCookie(U64.of(0));
		fmbRev.setPriority(FlowModUtils.PRIORITY_MAX);

        Match.Builder mbRev = sw.getOFFactory().buildMatch();
        mbRev.setExact(MatchField.ETH_TYPE, EthType.IPv4)
        .setExact(MatchField.IPV4_SRC, ipv4.getDestinationAddress())
        .setExact(MatchField.ETH_SRC, MacAddress.of(Utils.master.getMacAddress().getBytes()))
        .setExact(MatchField.IPV4_DST, ipv4.getSourceAddress());
        
        ArrayList<OFAction> actionListRev = new ArrayList<OFAction>();
        
        OFActionSetField setDlDstRev = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthSrc()
        	        .setValue(Utils.VIRTUAL_MAC)
        	        .build()
        	    )
        	    .build();
        actionListRev.add(setDlDstRev);

        OFActionSetField setNwDstRev = actions.buildSetField()
        	    .setField(
        	        oxms.buildIpv4Src()
        	        .setValue(ipv4.getDestinationAddress())
        	        .build()
        	    ).build();
        actionListRev.add(setNwDstRev);
        
        //System.out.println("[VA]Physical port number is "+pi.getMatch().get(MatchField.IN_PORT));
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
			//System.out.println("adv messagee from router: " + adv[0] + " priority:" + adv[1]);
			int priority;
			try {
				priority = Integer.parseInt(adv[1]);
			} catch(NumberFormatException ex) {
				System.out.println("the priority sent from the router can't be cast to an integer");
				return;
			}
			
			Router router = new Router(adv[0],ipv4.getSourceAddress(), eth.getSourceMACAddress(), priority, new Date().getTime());
			Utils.switchPorts.putIfAbsent(eth.getSourceMACAddress(), pi.getMatch().get(MatchField.IN_PORT));
			
			// master is null when no router are registered or all routers are down
			if(Utils.master == null) {
				System.out.println("A new master is elected: "+adv[0]);
				Utils.master = router;
				// set the timer
				setTimer();
			}
			else {
				// a new adv from current master is arrived
				if(Utils.master.getMacAddress().compareTo(router.getMacAddress()) == 0) {
					// reset the timer
					resetTimer();
				} else if(Utils.master.getPriority() < router.getPriority()) { // I have to check if its priority is better than the current master
					Utils.master = router;
					System.out.println("A new master is elected: "+adv[0]);
					// reset the timer
					resetTimer();
				}
			}
			Utils.routers.put(router.getMacAddress(), router);
		}
	}
	
	private String startElection() {
		if(Utils.master != null) {
			Utils.master.setPriority(-1);
			for(Map.Entry<MacAddress, Router> entry:Utils.routers.entrySet()) {
				if((new Date().getTime() - entry.getValue().getTimestamp()) < Utils.masterDownInterval && 
						entry.getValue().getPriority() > Utils.master.getPriority())
					Utils.master = entry.getValue();
			}
			if(Utils.master.getPriority() != -1) {
				resetTimer();
				return Utils.master.getName();
			}
			// no active routers are found
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