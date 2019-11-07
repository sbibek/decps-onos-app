package org.decps.app;
import com.google.common.collect.Maps;

import java.util.*;

public class PacketThrottle {
    // this class will track the throttle info
    Map<Integer, ThrottleInfo> throttle = Maps.newConcurrentMap();

    public boolean throttle(Integer id) {
        // now we will generate a random number which if even we will throttle
        Random rand = new Random();
        int n = rand.nextInt(99999);
        return (n%2 == 0);
    }

    public static class ThrottleInfo {
        Integer id;
        Integer throttleCount;
    }
}
