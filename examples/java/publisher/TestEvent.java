import java.util.LinkedHashMap;
import java.util.Map;

public class TestEvent extends Event {

    public TestEvent(String sourceId) {
        super(sourceId, "application/json", "Ztreamy-java-test", "Test event",
              new LinkedHashMap<String, Object>());
        getBody().put("timestamp", String.valueOf(System.nanoTime()));
    }
}
