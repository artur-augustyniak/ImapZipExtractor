package util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 *
 * @author aaugustyniak
 */
public class InstanceProvider {

    private static final Map<Class, Object> instances = new HashMap<>();

    private static CountDownLatch cdl = null;

    private static Map mapHandle;

    public static synchronized <T> T getInst(Class<T> clazz) {
        if (null == instances.get(clazz)) {
            try {
                instances.put(clazz, clazz.newInstance());

            } catch (ReflectiveOperationException ex) {
                throw new RuntimeException("Can't init type " + ex.getMessage());
            }
        }
        return (T) instances.get(clazz);
    }

    public static synchronized Map getSyncedMap() {
        if (null == mapHandle) {
            mapHandle = Collections.synchronizedMap(new HashMap());
        }
        return mapHandle;
    }

    public static synchronized CountDownLatch getCountDownLatchWith(int count) {
        if (null == cdl) {
            cdl = new CountDownLatch(count);
        }
        return cdl;
    }

    public static synchronized void resetLatch() {
        cdl = null;
    }

}
