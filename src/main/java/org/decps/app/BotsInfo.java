package org.decps.app;
import com.google.common.collect.Maps;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;

import java.util.*;
import java.lang.*;

public class BotsInfo {
    private int locked = 0;
    private static long lastReported = 0;
    private static int cncip = -2141209023; // 128.95.190.65
    private static int cncport = 2400;
    private static int memberCount = 10;
    private static int encounteredPkts = 0;

    // bots are those connected to the CNC 128.95.190.65:2400.
    List<Info> bots = new ArrayList<>();
    Map<String, Info> registeredBots = Maps.newConcurrentMap();

    Map<Integer, List<Info>> groups = Maps.newConcurrentMap();
    Map<Integer, Status> status = Maps.newConcurrentMap();
    Integer ACTIVE_GROUP = 0;

    private void createGroups() {
        Integer groupId = 0;
       List<Info> bi = new ArrayList<>();
        for(int i=0;i<bots.size();i++) {
            bots.get(i).group = groupId;
            bi.add(bots.get(i));
            if((i+1)%memberCount == 0 || i == bots.size()-1) {
                groups.put(groupId, bi);
                groupId++;
                bi = new ArrayList<>();
            }
        }

        // status to track the packet status in each group
        for(int i=0;i<groups.size();i++) {
            status.put(i, new Status());
        }

        System.out.println("[BotsInfo] groups created #"+groups.size());
    }

    public boolean isLocked(){
        return locked == 1;
    }

    private int count() {
        int i = 0;
            for (Map.Entry<Integer, Status> entry : status.entrySet()) {
                i+= entry.getValue().packetsCount;
            }
            return i;
    }

    public int groupCheck(int botIp, int botPort, MacAddress botMac ){
        encounteredPkts++;
        // this should run only if the bots are locked
        if(locked == 0) return -1;

        Info i = registeredBots.get(botMac.toString()+botPort);
        if(i != null) {
            // now check if this bot belongs to the current active group
            if(i.group == ACTIVE_GROUP) {
                // then we allow this packet as it belongs to current active group
                // first we update the timestamp
                // the first time the packet for this group is encountered, the timestamp will be 0, at that time never change the group
                Status s = status.get(ACTIVE_GROUP);
                s.lastEncountered = System.currentTimeMillis();
                s.packetsCount++;
                return 1;
            } else {
//                System.out.println("packets got for "+i.group+" but active group is "+ACTIVE_GROUP);
                // if the packet received is from another group, then we will check the time it took from last packet in the current
                // group. if the gap exceeds threshold say 500ms, then we will change the group
                Status s = status.get(ACTIVE_GROUP);
                if(System.currentTimeMillis() - s.lastEncountered > 1000){
                    // then lets change the group
                    ACTIVE_GROUP++;
                    System.out.println("[#G]"+ACTIVE_GROUP+" pkts count "+s.packetsCount+" encountered "+encounteredPkts+" processed "+count());
                    System.out.println("[status] switching to group "+ ACTIVE_GROUP);
                    if(ACTIVE_GROUP > status.size()-1){
                        System.out.println("group exceeded, so this is end of the experiment for all the groups so looping to first group");
                        ACTIVE_GROUP = 0;
                    }

                    return i.group == ACTIVE_GROUP?1:0;
                }

                return 0;
            }
        }

        return 0;
    }

    private void cleanup() {
        // if the bots didnt refresh its status in 60, it will be cleaned up
        List<Info> cleanUp = new ArrayList<>();
        long current = System.currentTimeMillis();
        for (Info bot : bots) {
           if(current-bot.lastSeen > 50000) {
               cleanUp.add(bot);
           }
        }

        // now lets cleanup
        for(Info bot: cleanUp) {
            bots.remove(bot);
            registeredBots.remove(bot.mac+bot.botPort);
        }
    }

    private void report() {
        long current = System.currentTimeMillis();
        if(current - lastReported > 5000) {
            if(locked == 0)
                cleanup();
            lastReported = current;
            System.out.println("[BotsInfo locked="+locked+"] no of bots connected: "+bots.size());
        }
    }

    public void registerIfBot(int srcIP, int srcPort, MacAddress sourceMac, int dstIP, int dstPort, MacAddress dstMac){
             if(locked == 1) { report(); return; }

            if(srcIP == cncip && srcPort == cncport) {
                // this means the cnc is communicating with bot, so lets register this bot
                String id = dstMac.toString()+dstPort;
                if(registeredBots.get(id) == null) {
                    // means we need to register
                    Info i = new Info();
                    i.botIP = dstIP;
                    i.botPort = dstPort;
                    i.mac = dstMac.toString();
                    i. lastSeen = System.currentTimeMillis();

                    bots.add(i);
                    registeredBots.put(id, i);
                } else {
                    // update the timestamp
                    Info i = registeredBots.get(id);
                    i.lastSeen = System.currentTimeMillis();
                }
                report();
                if(bots.size() > 100) {
                    locked = 1;
                    createGroups();
                }
            }
    }

    public static class Info {
        public int group = -1;
        public long lastSeen = 0;
        public int processed = 0;
        public String mac;
        public int botIP;
        public int botPort;
    }

    public static class Status {
        public long lastEncountered = 0; // timestamp
        public int packetsCount = 0;
    }
}
