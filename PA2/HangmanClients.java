import java.io.*;
import java.net.*;

public class HangmanClients {
    private Socket socket;
    private DataInputStream input;
    private DataOutputStream output;
    private String name;
    
    public HangmanClients(String address, int port) {
        try {
            socket = new Socket(address, port);
            System.out.println("Connected Successfully\n");

            //System.out.println("Enter username:");
            //BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            //name = br.readLine();

            input = new DataInputStream(socket.getInputStream());
            output = new DataOutputStream(socket.getOutputStream());

            // Send welcome message to the server
            //output.writeUTF("WELCOME " + name);

            // Start a new thread to handle server messageskay
            new Thread(new MessageHandler(input)).start();

            
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    public void startGame() {
        try {
            //Prompt the user to choose a word
            //System.out.println("Enter a word for the other player to guess:");
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            //String word = br.readLine().toUpperCase();
            
            // Send the word to the server
            //output.writeUTF("WORD " + word);

            // Play the game
            String line;
            while (true) {
                //System.out.println("Waiting for the other player to guess...");
                line = br.readLine().toUpperCase();

                // Send the guess to the server
                output.writeUTF(line);
            }
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        HangmanClients client = new HangmanClients("localhost", 8989);
        client.startGame();
    }
    
    class MessageHandler implements Runnable {
        private DataInputStream input;
        
        public MessageHandler(DataInputStream input) {
            this.input = input;
        }
        
        @Override
        public void run() {
            try {
                while (true) {
                    String message = input.readUTF();
                    String[] parts = message.split(" ");
                    
                    if (parts[0].equals("WORD")) {
                        System.out.println("The other player has chosen a word. Start guessing!");
                    } else if (parts[0].equals("GUESS")) {
                        System.out.println("The other player guessed: " + parts[1]);
                    } else {
                        System.out.println(message);
                    }
                }
            } catch (IOException e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }
}
