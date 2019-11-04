package org.decps.app;

import com.google.common.collect.Maps;
import org.onlab.packet.MacAddress;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

import javax.validation.constraints.Null;
import java.util.Map;

public class FlowAnalytics {
    private Map<Integer, PacketFlowRate>  flowRateMap = Maps.newConcurrentMap();


    public PacketFlowRate flow(int sourceAddress, int destinationAddress, int srcPort, int dstPort) {
        Integer id = sourceAddress+destinationAddress+srcPort+dstPort;
        PacketFlowRate pfr = flowRateMap.get(id);
        if(pfr == null) {
            pfr = new PacketFlowRate();
            pfr.id = id.intValue();
            pfr.packetCount = 1;
        } else {
            pfr.packetCount++;
        }
        flowRateMap.putIfAbsent(id, pfr);
         return pfr;
    }

    public static class PacketFlowRate {
        public int id;
        public int packetCount;
        public int average;

        public void log() {
            System.out.println("[#"+id+"] "+packetCount);
        }
    }
}
