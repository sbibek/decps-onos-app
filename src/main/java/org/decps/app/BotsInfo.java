package org.decps.app;
import com.google.common.collect.Maps;
import org.onlab.packet.IPv4;

import java.util.*;

public class BotsInfo {
    private static int cncip = -2141209023; // 128.95.190.65
    private static int cncport = 2400;

    // bots are those connected to the CNC 128.95.190.65:2400.
    List<Info> bots = new ArrayList<>();
    Map<Integer, Info> registeredBots = Maps.newConcurrentMap();

    public Info registerIfBot(int srcIP, int srcPort, int dstIP, int dstPort){
        int botip = -1,botport = -1;
        if(srcIP == cncip && srcPort == cncport ) {
            botip = dstIP; botport = dstPort;
        } else if (dstIP == cncip && dstPort == cncport) {
            botip = srcIP; botport = srcPort;
        }

        if(botip == -1 || botport == -1){
            return null;
        } else {
            // encountered the bot
            // now first we register the bot to the map so its lookup time is O(1).
            Integer botId = botip+botport;
            Info _bi = registeredBots.get(botId);
            if( _bi != null) {
                // means there is already a registered bot so ignore
                // also its no more new as we encountered it again
                _bi.isNew = false;
                return _bi;
            } else {
                // this is a new bot
                Info i = new Info();
                i.isNew = true;
                i.botIP = botip;
                i.botPort = botport;

                registeredBots.put(botId, i);
                bots.add(i);
                System.out.println("added bot "+ IPv4.fromIPv4Address(botip)+":"+botport+"\n");
                return i;
            }
        }

    }

    public static class Info {
        public boolean isNew = true; // if we encountered it just once, then its new else its not new
        public int botIP;
        public int botPort;
    }
}
