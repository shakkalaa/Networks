//import java.io.DataInputStream;
import java.net.*;
import java.util.*;
import java.io.*;

public class Clients{
    private Socket socket = null;
    private DataInputStream input = null;
    private DataOutputStream output = null;
    private String nameString;

    public Clients(String address, int port){
        try{

            
            socket = new Socket(address, port);
            System.out.println("Connected Successfully\n");

            System.out.println("Enter username:\n");

            input = new DataInputStream(System.in);

            nameString = input.readLine();

            output = new DataOutputStream(socket.getOutputStream());
            
            new Thread(new MesseageHandler(socket.getInputStream())).start();
            
            output.writeUTF((new Date()).toString() + " " +"Welcome " + nameString + "\n");


        }catch(Exception e){
             // TODO: handle exception
             System.out.println("Error" + e.getMessage());
        }
       String line = "";
        while (!line.equals("Bye")) {
            try {
                line = input.readLine();
                //output.writeUTF(line);
                output.writeUTF((new Date()).toString() + " " + nameString + ": " + line +"\n");

            } catch (IOException i) {
                // TODO: handle exception
                System.out.println(i);
            }
            
        }

        System.out.println("Goodbye " + nameString);
        
        try {
            input.close();
            output.close();
            socket.close();

        } catch (IOException ioException) {
            // TODO: handle exception
            System.out.println(ioException.getMessage());
        }
    }

    public static void main(String[] args) {

       // StopWatch stopWatch = new StopWatch();
        //stopWatch.start();

        new Clients("localhost", 8989);

        //stopWatch.stop();
        
        //System.out.println("Elapsed Time in minutes: "+ stopWatch.getTime());
    }

    class MesseageHandler implements Runnable{
        private final InputStream server;
    
        public MesseageHandler(InputStream server){
            this.server = server;
        }
    
        @Override
        public void run(){
            Scanner scan = new Scanner(server);
    
            while(scan.hasNextLine()){
                System.out.println(scan.nextLine());
            }
            scan.close();
        }
    }
    
}