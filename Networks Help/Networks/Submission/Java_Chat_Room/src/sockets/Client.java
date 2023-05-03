package sockets;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.util.Date;
import java.util.Scanner;

public class Client {

    private final String host;
    private final int port;

    public static void main(String[] args) throws IOException {
        new Client("127.0.0.1", 8989).run();
    }

    public Client(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void run() throws IOException {
        Socket client = new Socket(host, port);
        System.out.println("Client successfully connected to server!");

        new Thread(new ReceivedMessagesHandler(client.getInputStream())).start();
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter Name: ");
        String nickname = sc.nextLine();
        PrintStream output = new PrintStream(client.getOutputStream());
        output.println( (new Date()).toString()+"  "+"Welcome "+nickname);

        while (sc.hasNextLine()) {
            output.println( (new Date()).toString()+"  "+nickname + ": " + sc.nextLine());
        }

        output.close();
        sc.close();
        client.close();
    }
}

class ReceivedMessagesHandler implements Runnable {

    private final InputStream server;

    public ReceivedMessagesHandler(InputStream server) {
        this.server = server;
    }

    @Override
    public void run() {
        Scanner s = new Scanner(server);
        while (s.hasNextLine()) {
            System.out.println(s.nextLine());
        }
        s.close();
    }
}
