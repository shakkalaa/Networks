package sockets;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Server {

    private final int port;
    private final List<PrintStream> clients;

    public static void main(String[] args) throws IOException {
        new Server(8989).run();
    }

    public Server(int port) {
        this.port = port;
        this.clients = new ArrayList<>();
    }

    public void run() throws IOException {
        ServerSocket server = new ServerSocket(port) {
            protected void finalize() throws IOException {
                this.close();
            }
        };
        System.out.println("Port 8989 is now open.");

        while (true){
            Socket client = server.accept();
            System.out.println("Connection established with client: " + client.getInetAddress().getHostAddress());
            System.out.print("");
            this.clients.add(new PrintStream(client.getOutputStream()));
            new Thread(new ClientHandler(this, client.getInputStream())).start();
        }
    }

    void broadcastMessages(String msg) {
        for (PrintStream client : this.clients) {
            client.println(msg);
        }
    }
}

class ClientHandler implements Runnable {

    private final Server server;
    private final InputStream client;

    public ClientHandler(Server server, InputStream client) {
        this.server = server;
        this.client = client;
    }

    @Override
    public void run() {
        String message;
        Scanner sc = new Scanner(this.client);
        while (sc.hasNextLine()) {
            message = sc.nextLine();
            server.broadcastMessages(message);
            System.out.println(message);
        }

        sc.close();
    }
}
