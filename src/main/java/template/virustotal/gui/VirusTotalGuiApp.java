package template.virustotal.gui;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

public class VirusTotalGuiApp extends Application {

	private static Stage primaryStage;
	private VirusTotalGuiController controller;
	
	@Override
	public void start(Stage primaryStage) throws Exception {
		
		VirusTotalGuiApp.primaryStage = primaryStage;
		
		controller = new VirusTotalGuiController();
		
		Scene scene = new Scene(controller.getView(), 640,480);
		
		primaryStage.setTitle("VirusTotal GUI v1.0");
		primaryStage.setScene(scene);
		primaryStage.getIcons().add(new Image(getClass().getResource("/images/virustotal.png").toExternalForm()));
		primaryStage.setResizable(false);
		primaryStage.show();
		
	}
	
	public static void main(String[] args) {
		launch(args);
	}
	
	public static Stage getPrimaryStage() {
		return primaryStage;
	}

}
