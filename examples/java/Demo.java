import dev.acciv.keygate.KeyGateClient;

public class Demo {
    public static void main(String[] args) throws Exception {
        KeyGateClient client = new KeyGateClient("http://127.0.0.1:8080", "kg_master_local", "demo-java");
        System.out.println("health: " + client.health());
        System.out.println("resolve: " + client.resolve("openai", "send", 60));
        System.out.println("providers: " + client.providers());
    }
}
