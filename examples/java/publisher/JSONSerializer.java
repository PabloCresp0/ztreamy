import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import com.google.gson.Gson;

public class JSONSerializer implements Serializer {

    private Gson gson;

    private static Charset charsetUTF8 = Charset.forName("UTF-8");

    public JSONSerializer() {
        gson = new Gson();
    }

    public String contentType() {
        return "application/json";
    }

    public byte[] serialize(Event event) {
        return gson.toJson(event.toMap()).getBytes(charsetUTF8);
    }

    public byte[] serialize(Event[] events) {
        List<Map<String, Object>> maps = new ArrayList<Map<String, Object>>();
        for (Event event: events) {
            maps.add(event.toMap());
        }
        return gson.toJson(maps).getBytes(charsetUTF8);
    }

    public static void main(String[] args) throws IOException {
        Event event = new Event(Event.createUUID(), Event.createUUID(),
                                "text/plain", "Ztreamy-test",
                                "Test event");
        event.setBody("Test body.");
        Serializer serializer = new JSONSerializer();
        System.out.write(serializer.serialize(event));
    }
}
