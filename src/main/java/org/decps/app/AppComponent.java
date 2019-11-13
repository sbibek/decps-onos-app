/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.decps.app;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import org.glassfish.jersey.internal.jsr166.Flow;
import org.onlab.packet.*;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.packet.*;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static org.onlab.util.Tools.get;


/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {SomeInterface.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class AppComponent implements SomeInterface {

    private final int mode = 1; // 0 => hub, 1 => switch

    private final Logger log = LoggerFactory.getLogger(getClass());

    private FlowAnalytics analytics = new FlowAnalytics();
    private BotsInfo botsInfo = new BotsInfo();
    private PacketThrottle packetThrottle = new PacketThrottle();
    /** Some configurable property. */
    private String someProperty;

    private Integer EXP_RANDOM = 0;
    private Integer EXP_WEIGHTED = 1;
    private Integer EXP_GROUP = 2;


    private List<Integer> weightedList = new ArrayList<>();

    private Integer EXPERIMENT = EXP_GROUP;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;


    protected Map<DeviceId, Map<MacAddress, PortNumber>>  mactables = Maps.newConcurrentMap();
    private ApplicationId appId;
    private PacketProcessor processor;

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        log.info("Started");
        appId = coreService.getAppId("org.decps.app");
        log.info("(application id, name)  " + appId.id()+", " + appId.name());

        processor = new SwitchPacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(3));

        // now lets restrict packet to ipv4 and arp
        packetService.requestPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_IPV4).build(), PacketPriority.REACTIVE, appId, Optional.empty());
        packetService.requestPackets(DefaultTrafficSelector.builder().matchEthType(Ethernet.TYPE_ARP).build(), PacketPriority.REACTIVE, appId, Optional.empty());


        // initialize the weighted list
        // current, 1:40%, 0: 60%
        weightedList.add(1);
        weightedList.add(1);
        weightedList.add(1);
        weightedList.add(1);
        weightedList.add(0);
        weightedList.add(0);
        weightedList.add(0);
        weightedList.add(0);
        weightedList.add(0);
        weightedList.add(0);
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        log.info("Stopped");
        packetService.removeProcessor(processor);
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

    private class SwitchPacketProcessor implements PacketProcessor {

        @java.lang.Override
        public void process(PacketContext context) {
            InboundPacket iPacket = context.inPacket();
            Ethernet ethPacket = iPacket.parsed();
            boolean reject = false;
            if(ethPacket.getEtherType() == Ethernet.TYPE_IPV4)  {
                IPv4 ipPacket = (IPv4) ethPacket.getPayload();
                // now current point of interest is just TCP packets
                if(ipPacket.getProtocol() == IPv4.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP)ipPacket.getPayload();

                    if(EXPERIMENT == EXP_GROUP) {
                        botsInfo.registerIfBot(ipPacket.getSourceAddress(), tcpPacket.getSourcePort(), ethPacket.getSourceMAC(), ipPacket.getDestinationAddress(), tcpPacket.getDestinationPort(), ethPacket.getDestinationMAC());
                    }

//                    tcpPacket.getFlags()
                    if(ipPacket.getSourceAddress() == -2141209023 && tcpPacket.getSourcePort() == 2400) {
                        // now lets filter to the flags
                        // we just want the data related to PSH ACK as it contains the payload
                        // also we want the packet to have the data bytes larger than 2 ( learnt from the packet inspection)
                        if(tcpPacket.getFlags() == 24 && tcpPacket.getPayload().serialize().length > 2) {
                            // means there is a attack payload from CNC to bots
                            if(EXPERIMENT == EXP_RANDOM) {
                                Random rand = new Random();
                                int n = rand.nextInt(99999);
                                reject = (n % 2 == 0);
                            } else if( EXPERIMENT == EXP_WEIGHTED) {
                                Random rand = new Random();
                                int n = rand.nextInt(9);
                                reject = (weightedList.get(n) == 0);
                            } else if(EXPERIMENT == EXP_GROUP) {
                                // this is hugely complex as we need to set the groups

                            }
                            System.out.println("[cnc->bot #"+EXPERIMENT+"] "+IPv4.fromIPv4Address(ipPacket.getDestinationAddress())+":"+tcpPacket.getDestinationPort()+" status: "+(reject?"rejected":"allowed"));

                        }
                    }
//                   FlowAnalytics.PacketFlowRate fr = analytics.flow(ipPacket.getSourceAddress(), ipPacket.getDestinationAddress(), tcpPacket.getSourcePort(), tcpPacket.getDestinationPort());
//                    System.out.println("("+IPv4.fromIPv4Address(ipPacket.getSourceAddress())+"="+ ipPacket.getSourceAddress()+","+tcpPacket.getSourcePort()+ ") -> (" + IPv4.fromIPv4Address(ipPacket.getDestinationAddress())+","+tcpPacket.getDestinationPort()+")" );
//                    fr.log();
//
//                   BotsInfo.Info info = botsInfo.registerIfBot(ipPacket.getSourceAddress(), tcpPacket.getSourcePort(), ipPacket.getDestinationAddress(), tcpPacket.getDestinationPort());
//                   if(info != null && info.isNew == false) {
//                        // means the new packet will be allowed first
//                       if(packetThrottle.throttle(Integer.valueOf(info.botIP+info.botPort)) == true){
////                            this means reject the packet
//                           reject = true;
//                           System.out.println("Throttling packet from "+IPv4.fromIPv4Address(info.botIP)+"@"+info.botPort);
//                       } else {
//                           System.out.println("Allowing packet from "+IPv4.fromIPv4Address(info.botIP)+"@"+info.botPort);
//                           reject = false;
//                       }
//                   }
                }
            }

        if(!reject) {
//            log.info("(received from) "+context.inPacket().receivedFrom().toString());
            initMacTable(context.inPacket().receivedFrom());
            actLikeSwitch(context);
        }
        }

        public void actLikeHub(PacketContext context){
           context.treatmentBuilder().setOutput(PortNumber.FLOOD) ;
           context.send();
        }

        public void actLikeSwitch(PacketContext context) {
            short type =  context.inPacket().parsed().getEtherType();

            ConnectPoint cp = context.inPacket().receivedFrom();
            Map<MacAddress, PortNumber> macTable = mactables.get(cp.deviceId());
            MacAddress srcMac = context.inPacket().parsed().getSourceMAC();
            MacAddress dstMac = context.inPacket().parsed().getDestinationMAC();
            macTable.put(srcMac, cp.port());
            PortNumber outPort = macTable.get(dstMac);

            if(outPort != null) {
//                log.info("("+dstMac+") is a on port "+ outPort + "[ stats: device count #"+mactables.size()+"]");
                context.treatmentBuilder().setOutput(outPort);
                context.send();
            } else {
//                log.info("("+dstMac+") is not yet mapped, so flooding"+ "[ stats: device count #"+mactables.size()+"]");
                // means just flood as we dont have mapping yet
                actLikeHub(context);
            }
        }

        private void initMacTable(ConnectPoint cp){
            mactables.putIfAbsent(cp.deviceId(), Maps.newConcurrentMap());
        }
    }

}
