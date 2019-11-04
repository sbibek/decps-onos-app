package org.decps.app;

import com.google.common.collect.Maps;
import org.onlab.packet.MacAddress;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

import javax.validation.constraints.Null;
import java.util.Map;
import java.util.Date;

public class FlowAnalytics {
    private Map<Integer, PacketFlowRate>  flowRateMap = Maps.newConcurrentMap();


    public PacketFlowRate flow(int sourceAddress, int destinationAddress, int srcPort, int dstPort) {
        Integer id = sourceAddress+destinationAddress+srcPort+dstPort;
        PacketFlowRate pfr = flowRateMap.get(id);
        if(pfr == null) {
            pfr = new PacketFlowRate();
            pfr.id = id.intValue();
            pfr.average = 0;
            pfr.packetCount = 1;
        } else {
            pfr.packetCount++;
            long elapsedTime = System.currentTimeMillis() - pfr.startTime;
//            System.out.println("epapsed time "+elapsedTime);
            pfr.average = pfr.packetCount*1000.0f/elapsedTime;
        }
        flowRateMap.putIfAbsent(id, pfr);
         return pfr;
    }

    public static class PacketFlowRate {
        public int id;
        public long startTime = System.currentTimeMillis();
        public int packetCount;
        public float average;

        public void log() {
            System.out.println("[#"+id+"] total count:"+packetCount+", avg p/sec:"+average);
        }
    }
}
