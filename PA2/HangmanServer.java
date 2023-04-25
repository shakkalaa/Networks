import java.io.*;
import java.net.*;

public class HangmanServer {
    private ServerSocket serverSocket;
    private Socket player1, player2;
    private DataInputStream input1, input2;
    private DataOutputStream output1, output2;
    private String word;
    private String guess;
    private int turn;
    private boolean gameEnded;
    
    public HangmanServer(int port) {
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("Server started. Waiting for players...");
            gameEnded = false;
            
            // Wait for first player to connect
            player1 = serverSocket.accept();
            System.out.println("Player 1 connected.");
            
            // Set up input/output streams for player 1
            input1 = new DataInputStream(player1.getInputStream());
            output1 = new DataOutputStream(player1.getOutputStream());
            
            // Send welcome message to player 1
            output1.writeUTF("Welcome to WordGuess! Waiting for another player to connect...");
            
            // Wait for second player to connect
            player2 = serverSocket.accept();
            System.out.println("Player 2 connected.");
            
            // Set up input/output streams for player 2
            input2 = new DataInputStream(player2.getInputStream());
            output2 = new DataOutputStream(player2.getOutputStream());
            
            // Send welcome message to player 2
            output1.writeUTF("Enter a word for the other player to guess:");
            output2.writeUTF("Welcome to WordGuess! Waiting for player 1 to enter a word...");

            
            // Wait for player 1 to enter a word
            String player1word = input1.readUTF();
            

            output2.writeUTF("Enter a word for the other player to guess:");

            // Wait for player 2 to enter a word
            String player2word = input2.readUTF();
            

            // Notify player 1 that the word has been set
            //output1.writeUTF("WORD " + player1word);
            
            // Notify player 2 that the word has been set
            //output2.writeUTF("WORD " + player2word);
            
            // Set turn
            turn = 1;
            
            // Start game loop
            while (!gameEnded) {
                if (turn == 1) {
                    output1.writeUTF("Its your turn, Player 1!");
                    // Wait for player 1 to enter a guess
                   String guess = input1.readUTF();
        
                    if (guess.equals(player2word)) {
                        // Player 1 guessed the word
                        output1.writeUTF("WINNER");
                        output2.writeUTF("LOSER " + guess);
                        gameEnded = true;
                        break;
                    } else {
                        // Send the guess to player 2
                        output2.writeUTF("GUESS " + guess);

                        // Switch turn to player 2
                        turn = 2;
                    }
                    
                } else {
                    output2.writeUTF("Its your turn, Player 2!");
                    // Wait for player 2 to enter a guess
                    String guess = input2.readUTF();

                    if (guess.equals(player1word)) {
                        // Player 2 guessed the word
                        output1.writeUTF("LOSER " + guess);
                        output2.writeUTF("WINNER");
                        gameEnded = true;
                        break;
                    } else {
                        // Send the guess to player 1
                        output1.writeUTF("GUESS " + guess);
                        // Switch turn to player 1
                        turn = 1;
                    }
                    
                }
            }
            
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        new HangmanServer(8989);
    }
}
