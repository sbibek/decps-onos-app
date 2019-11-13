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

    // bots are those connected to the CNC 128.95.190.65:2400.
    List<Info> bots = new ArrayList<>();
    Map<String, Info> registeredBots = Maps.newConcurrentMap();

    Map<Integer, List<Info>> groups = Maps.newConcurrentMap();

    private void createGroups() {
        Integer groupId = 0;
       List<Info> bi = new ArrayList<>();
        for(int i=0;i<bots.size();i++) {
            bi.add(bots.get(i));
            if((i+1)%memberCount == 0 || i == bots.size()-1) {
                groups.put(groupId, bi);
                groupId++;
                bi = new ArrayList<>();
            }
        }

        System.out.println("[BotsInfo] groups created #"+groups.size());
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
        public long lastSeen = 0;
        public int processed = 0;
        public String mac;
        public int botIP;
        public int botPort;
    }
}
