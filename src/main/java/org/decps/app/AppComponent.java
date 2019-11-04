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
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
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

import java.util.Map;
import java.util.Dictionary;
import java.util.Properties;
import java.util.Optional;

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

    /** Some configurable property. */
    private String someProperty;

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
            if(ethPacket.getEtherType() == Ethernet.TYPE_IPV4)  {
                IPv4 ipPacket = (IPv4) ethPacket.getPayload();
                // now current point of interest is just TCP packets
                if(ipPacket.getProtocol() == IPv4.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP)ipPacket.getPayload();
                   FlowAnalytics.PacketFlowRate fr = analytics.flow(ipPacket.getSourceAddress(), ipPacket.getDestinationAddress(), tcpPacket.getSourcePort(), tcpPacket.getDestinationPort());
                    System.out.println("("+IPv4.fromIPv4Address(ipPacket.getSourceAddress()) +","+tcpPacket.getSourcePort()+ ") -> (" + IPv4.fromIPv4Address(ipPacket.getDestinationAddress())+","+tcpPacket.getDestinationPort()+")"+" id::"+(ipPacket.getSourceAddress()+ipPacket.getDestinationAddress()+tcpPacket.getSourcePort()+tcpPacket.getDestinationPort()) );
                    fr.log();
                }
            }


//            log.info("(received from) "+context.inPacket().receivedFrom().toString());
            initMacTable(context.inPacket().receivedFrom());
            actLikeSwitch(context);
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
