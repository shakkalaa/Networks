import java.net.*;
import java.util.*;
//import java.util.List;
import java.io.*;

public class Servers{
    private Socket socket = null;
    private ServerSocket server = null;
    private DataInputStream input = null;
    //private final int port;
    private final List<PrintStream> clients;

    public Servers(int port){
        
        //this.port = port;
        this.clients = new ArrayList<>();

        try {
            
            server = new ServerSocket(port);
            System.out.print("Server Started\n");
            System.out.println("Waiting client...");

             

            while (true) {
                socket = server.accept();
            
                System.out.println("Client accepted");

                System.out.println("Connection: " + socket.getInetAddress().getHostAddress() + "\n");
                System.out.print("");
                (this.clients).add(new PrintStream(socket.getOutputStream()));
                
                

                new Thread(new ClientHandler(this, socket.getInputStream())).start();
                
                     
            }
           
        } catch (Exception e) {
            // TODO: handle exception
            System.out.println(e.getMessage());
        }
       

        
    } 

    void broadcastMessages(String messageString){
        for (PrintStream client : this.clients) {
                client.println(messageString);      
        }
    }
    public static void main(String[] args) {
        new Servers(8989);
    }


    class ClientHandler implements Runnable{
        private final Servers server;
        private final InputStream client;
        private DataInputStream input;

        public ClientHandler(Servers servers, InputStream inputStream){
            this.server = servers;
            this.client = inputStream;
           //this.input = input;
        }

        public void run(){
            String word = input.readUTF();
            String guess;
            
            input = new DataInputStream(new BufferedInputStream(client));

            try {
                while (true) {
                    
                    guess = input.readUTF();

                    //String message = "";
                    if (guess.contains(word)) {

                        
                    }else{

                    server.broadcastMessages("Try Again");
                    System.out.println(messageString);
                    }     

                }
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                input.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
      
        }
    }
}