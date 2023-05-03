import java.util.Random;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import javafx.stage.Stage;

public class fillerBoard extends Application{
	
    private final int ROWS = 7;
    private final int COLS = 8;
    private final String[] COLORS = {"cyan", "green", "black", "yellow", "orange", "red"};

    private int[][] board = new int[ROWS][COLS];
    private int[] scores = new int[2];
    private int currentPlayer = 0;
    private Button[] fillButtons = new Button[6];

    private GridePane gameBoard;
    private Text player1Score;
    private Text player2Score;

	//private Button[] fillColors;
	//private Rectangle startingBlock;
    //private boolean player1Turn = true;


    @Override
    public void start(Stage primaryStage){

        //Create the UI components
        gameBoard = createGameBoard();
        HBox fillColors = createFillColors();

        player1Score = new Text("Player 1: 0");
        player2Score = new Text("Player 2: 0");

        //Add the components to a VBox
        VBox root = new VBox();
        root.getChildren().addAll(gameBoard, fillColors, player1Score, player2Score);

        //Set the scene and show the stage
        Scene scene = new Scene(root, 400, 500);
        primaryStage.setScene(scene);
        primaryStage.show();

    }

    private GridPane createGameBoard(){
        
        GridPane grid = new GridPane();
        //grid.setPadding(new Inserts(10));
        grid.setHgap(5);
        grid.setVgap(5);

        //Initialize the board with random colors
        Random random = new Random();

        for (int row = 0; row < ROWS; row++) {
            for(int col = 0; col < COLS; col++){
                
                int colorIndex = randomnextInt(COLORS.length);
                board[row][col] = colorIndex;

                java.awt.Button button = new Button();
                button.setPreferredSize(40, 40);
                button.setStyle("-fx-background-color: " + COLORS[colorIndex] + ";");
                gird.setRowIndex(button, row);
                grid.setColumnIndex(buton, col);
                grid.getChildren().add(button);
            }
        }

        //set the starting blocks for each player
        board[0][0] += 2;
        board[ROWS -1][0] += 1;

        return grid;

    }
    private HBox createFillColors() {
        HBox hbox = new HBox(10);
        hbox.setAlignment(Pos.CENTER);

        // Initialize the fill color buttons and add event listeners
        for (int i = 0; i < fillButtons.length; i++) {
            fillButtons[i] = new Button();
            fillButtons[i].setPrefSize(40, 40);
            fillButtons[i].setStyle("-fx-background-color: " + COLORS[i] + ";");
            final int colorIndex = i;
            fillButtons[i].setOnAction(e -> handlePlayerTurn(colorIndex));
            hbox.getChildren().add(fillButtons[i]);
        }

        return hbox;
    }

    private void handlePlayerTurn(int chosenColor) {

        // Get the current player's starting block
        int startingRow = currentPlayer == 0 ? 0 : ROWS - 1;
        int startingCol = 0;
        int startingColor = board[startingRow][startingCol];

        // Merge the starting block with adjacent blocks of the chosen color
        int mergedBlocks = 0;

        boolean[][] visited = new boolean[ROWS][COLS];
        mergedBlocks(startingRow, startingCol, startingColor, chosenColor, visited);

        mergeBlocks += scores[currentPlayer];

       

        //Update the game board and scores
        updateBoard(chosenColor, visited);
        scores[currentPlayer] += mergedBlocks;

        // Update the UI to show the new score
        updateUI();

        //Check for the end of the game
        boolean isGameOver = true;
        for (int row = 0; row < ROWS; row++) {
            for (int col = 0; col < COLS; col++) {
                if (board[row][col] != chosenColor) {
                    isGameOver = false;
                }
            }    
        }
        if (isGameOver) {
            System.out.println("Game over!");
        }
        //switch to the other players turn
        currentPlayer = (currentPlayer + 1) %2;

    }
    
    
    private void updateUI() {
        //Update the score labels
        player1Score.setText("Player 1:" + scores[0]);
        player2Score.setText("Player 2:" + scores[1]);

        //Update the color of each button on the game board
        
        for (int row = 0; row < ROWS; row++) {
            for (int col = 0; col < COLS; col++) {
                int colorIndex = board[row][col];
                if (colorIndex != -1) {
                    Button button = (Button) gameBoard.getChildren()get(row * COLS + col);
                    button.setStyle("-fx-background-color: " + COLORS[colorIndex] + ";");
                    
                }
            }
        }
    }

    private void updateBoard(int chosenColor, boolean[][] visited) {
        for (int row = 0; row < ROWS; row++) {
            for (int col = 0; col < COLS; col++) {
                if (visited[row][col]) {
                    board[row][col] = chosenColor;
                }
            }
        }
    }
    

    private void mergedBlocks(int row, int col, int startingColor, int chosenColor, boolean[][] visited) {
        if (row < 0 || row >= ROWS || col < 0 || col >= COLS || visited[row][col] || board[row][col] != startingColor) {
            return;
        }

        visited[row][col] = true;
        scores[currentPlayer]++;
        mergedBlocks(row -1, col, startingColor, chosenColor, visited);
        mergedBlocks( row + 1, col, startingColor, chosenColor, visited);
        mergedBlocks(row, col - 1, startingColor, chosenColor, visited);
        mergedBlocks(row, col + 1, startingColor, chosenColor, visited);

        if (startingColor == chosenColor) {
            board[row][col] = -1;
            
        }
    }

    public static void main(String[] args) {
        launch(args);
    }

}