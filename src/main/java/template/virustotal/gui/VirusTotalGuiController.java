package template.virustotal.gui;

import java.awt.Desktop;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.TimeUnit;

import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.dto.VirusScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;

public class VirusTotalGuiController implements Initializable {

	@FXML
	private BorderPane view;

	@FXML
	private Button viewOnlineReportButton;

	@FXML
	private TabPane tabPane;

	@FXML
	private Tab optionsTab;

	@FXML
	private PasswordField apiKeyTextField;

	@FXML
	private TextField urlTextField;

	@FXML
	private TextField fileTextField;

    @FXML
    private Button browseFileButton;
    
	@FXML
	private Button urlReportButton;

	@FXML
	private Button fileReportButton;

	@FXML
	private Tab tabReport;

	@FXML
	private TextArea reportTextArea;

	@FXML
	private Button saveReportButton;

	// menu

	@FXML
	void onAuthorGuiAction(ActionEvent event) {
		try {
			Desktop.getDesktop().browse(new URL("https://github.com/aitorcastel").toURI());
		} catch (Exception e) {
		}

	}

	@FXML
	void onAuthorLibraryAction(ActionEvent event) {
		try {
			Desktop.getDesktop().browse(new URL("https://github.com/kdkanishka").toURI());
		} catch (Exception e) {
		}
	}
    @FXML
    void onbrowseFileButton(ActionEvent event) {
		try {
			FileChooser selectFile = new FileChooser();
			selectFile.setInitialDirectory(new File("."));
			selectFile.getExtensionFilters().add(new ExtensionFilter("All the files", "*"));
			File file = selectFile.showOpenDialog(VirusTotalGuiApp.getPrimaryStage());
			if (file != null) {
				fileTextField.setText(file.getAbsolutePath());

			}
		} catch (Exception e1) {
			e1.printStackTrace();
			Alert error = new Alert(AlertType.ERROR);
			error.initOwner(VirusTotalGuiApp.getPrimaryStage());
			error.setTitle("Save report");
			error.setHeaderText("Save report failed.");
			error.setContentText(e1.getMessage());
			error.showAndWait();
		}

    }
	@FXML
	void onsaveReportButton(ActionEvent event) {

		try {
			FileChooser guardarDialog = new FileChooser();
			guardarDialog.setInitialDirectory(new File("."));
			guardarDialog.getExtensionFilters()
					.add(new ExtensionFilter("Report VirusTotal history (*.virushistory)", "*.virushistory"));
			guardarDialog.getExtensionFilters().add(new ExtensionFilter("All the files", "*"));
			File file = guardarDialog.showSaveDialog(VirusTotalGuiApp.getPrimaryStage());
			if (file != null) {
				BufferedWriter bf = new BufferedWriter(new FileWriter(file.getAbsoluteFile()));
				bf.write(reportTextArea.getText());
				bf.flush();
				bf.close();

			}
		} catch (Exception e1) {
			e1.printStackTrace();
			Alert error = new Alert(AlertType.ERROR);
			error.initOwner(VirusTotalGuiApp.getPrimaryStage());
			error.setTitle("Save report");
			error.setHeaderText("Save report failed.");
			error.setContentText(e1.getMessage());
			error.showAndWait();
		}
	}

	@FXML
	void onfileReportButton(ActionEvent event) {

		try {
			VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(apiKeyTextField.getText());
			VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

			ScanInfo scanInformation = virusTotalRef.scanFile(new File(fileTextField.getText()));
			// report generation

			// wait 5 seconds

			TimeUnit.SECONDS.sleep(5);

			//System.out.println("resourceWeB: "+scanInformation.getResource());
			//String resource = "6f5c2a8e487019b59ec05ed627502b9ac3085b91a5567e3f447d93681dd15e7e";
			
			String resource = scanInformation.getResource();
			
			
			FileScanReport report = virusTotalRef.getScanReport(resource);
			reportTextArea.setText(null);
			reportTextArea.appendText("REPORT ---------------------------------------" + "\n");
			reportTextArea.appendText("MD5 :\t" + report.getMd5() + "\n");
			reportTextArea.appendText("Perma link :\t" + report.getPermalink() + "\n");
			reportTextArea.appendText("Resource :\t" + report.getResource() + "\n");
			reportTextArea.appendText("Scan Date :\t" + report.getScanDate() + "\n");
			reportTextArea.appendText("Scan Id :\t" + report.getScanId() + "\n");
			reportTextArea.appendText("SHA1 :\t" + report.getSha1() + "\n");
			reportTextArea.appendText("SHA256 :\t" + report.getSha256() + "\n");
			reportTextArea.appendText("Verbose Msg :\t" + report.getVerboseMessage() + "\n");
			reportTextArea.appendText("Response Code :\t" + report.getResponseCode() + "\n");
			reportTextArea.appendText("Positives :\t" + report.getPositives() + "\n");
			reportTextArea.appendText("Total :\t" + report.getTotal() + "\n");

			reportTextArea.appendText("DETAILED SCANNER -------------------------------" + "\n");
			Map<String, VirusScanInfo> scans = report.getScans();
			for (String key : scans.keySet()) {
				VirusScanInfo virusInfo = scans.get(key);
				reportTextArea.appendText("Scanner : " + key + "\n");
				reportTextArea.appendText("\t\t Resut : " + virusInfo.getResult() + "\n");
				reportTextArea.appendText("\t\t Update : " + virusInfo.getUpdate() + "\n");
				reportTextArea.appendText("\t\t Version :" + virusInfo.getVersion() + "\n");
			}
			
			Alert alert = new Alert(AlertType.INFORMATION);
			alert.setTitle("INFO");
			alert.setHeaderText("Se ha generado correctamente su reporte");
			alert.setContentText("Espere 5 minutos para que los escaneres analicen su fichero y vuelva a relanzar el escaneo para obtener su reporte");
			alert.showAndWait();

		}

		catch (APIKeyNotFoundException ex) {
			System.err.println("API Key not found! " + ex.getMessage());
			
			Alert alert = new Alert(AlertType.ERROR);
			alert.setTitle("ERROR");
			alert.setHeaderText("API Key not found!");
			alert.setContentText(ex.getMessage());
			alert.showAndWait();
			
		} catch (UnsupportedEncodingException ex) {
			System.err.println("Unsupported Encoding Format!" + ex.getMessage());
			
			Alert alert = new Alert(AlertType.ERROR);
			alert.setTitle("ERROR");
			alert.setHeaderText("Unsupported Encoding Format");
			alert.setContentText(ex.getMessage());
			alert.showAndWait();
			
		} catch (UnauthorizedAccessException ex) {
			System.err.println("Invalid API Key!" + ex.getMessage());
			
			Alert alert = new Alert(AlertType.ERROR);
			alert.setTitle("ERROR");
			alert.setHeaderText("Invalid API Key!");
			alert.setContentText(ex.getMessage());
			alert.showAndWait();
			
		} catch (Exception ex) {
			System.err.println("Something Bad Happened! " + ex.getMessage());
			
			Alert alert = new Alert(AlertType.ERROR);
			alert.setTitle("ERROR");
			alert.setHeaderText("Something Bad Happened! ");
			alert.setContentText(ex.getMessage());
			alert.showAndWait();
		}
		
	}

	@FXML
	void onurlReportButton(ActionEvent event) {

		try {
			VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(apiKeyTextField.getText());
			VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

			String urls[] = { urlTextField.getText() };
			
			// report generation

			// wait 5 seconds

			TimeUnit.SECONDS.sleep(5);

			FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);
			for (FileScanReport report : reports) {
				if (report.getResponseCode() == 0) {
					continue;
				}
				reportTextArea.setText(null);
				reportTextArea.appendText("REPORT ---------------------------------------" + "\n");
				reportTextArea.appendText("MD5 :\t" + report.getMd5() + "\n");
				reportTextArea.appendText("Perma link :\t" + report.getPermalink() + "\n");
				reportTextArea.appendText("Resource :\t" + report.getResource() + "\n");
				reportTextArea.appendText("Scan Date :\t" + report.getScanDate() + "\n");
				reportTextArea.appendText("Scan Id :\t" + report.getScanId() + "\n");
				reportTextArea.appendText("SHA1 :\t" + report.getSha1() + "\n");
				reportTextArea.appendText("SHA256 :\t" + report.getSha256() + "\n");
				reportTextArea.appendText("Verbose Msg :\t" + report.getVerboseMessage() + "\n");
				reportTextArea.appendText("Response Code :\t" + report.getResponseCode() + "\n");
				reportTextArea.appendText("Positives :\t" + report.getPositives() + "\n");
				reportTextArea.appendText("Total :\t" + report.getTotal() + "\n");

				reportTextArea.appendText("DETAILED SCANNER -------------------------------" + "\n");
				Map<String, VirusScanInfo> scans = report.getScans();
				for (String key : scans.keySet()) {
					VirusScanInfo virusInfo = scans.get(key);
					reportTextArea.appendText("Scanner : " + key + "\n");
					reportTextArea.appendText("\t\t Resut : " + virusInfo.getResult() + "\n");
					reportTextArea.appendText("\t\t Update : " + virusInfo.getUpdate() + "\n");
					reportTextArea.appendText("\t\t Version :" + virusInfo.getVersion() + "\n");
				}
			}
			
			Alert alert = new Alert(AlertType.INFORMATION);
			alert.setTitle("INFO");
			alert.setHeaderText("Se ha generado correctamente su reporte");
			alert.setContentText("Vaya a la pestaña Basic Report para ver el resultado");
			alert.showAndWait();

		}

		catch (APIKeyNotFoundException ex) {
			System.err.println("API Key not found! " + ex.getMessage());
			
			Alert alert = new Alert(AlertType.ERROR);
			alert.setTitle("ERROR");
			alert.setHeaderText("API Key not found!");
			alert.setContentText(ex.getMessage());
			alert.showAndWait();
			
		} catch (UnsupportedEncodingException ex) {
			System.err.println("Unsupported Encoding Format!" + ex.getMessage());
			
			Alert alert = new Alert(AlertType.ERROR);
			alert.setTitle("ERROR");
			alert.setHeaderText("Unsupported Encoding Format");
			alert.setContentText(ex.getMessage());
			alert.showAndWait();
			
		} catch (UnauthorizedAccessException ex) {
			System.err.println("Invalid API Key!" + ex.getMessage());
			
			Alert alert = new Alert(AlertType.ERROR);
			alert.setTitle("ERROR");
			alert.setHeaderText("Invalid API Key!");
			alert.setContentText(ex.getMessage());
			alert.showAndWait();
			
		} catch (Exception ex) {
			System.err.println("Something Bad Happened! " + ex.getMessage());
			
			Alert alert = new Alert(AlertType.ERROR);
			alert.setTitle("ERROR");
			alert.setHeaderText("Something Bad Happened! ");
			alert.setContentText(ex.getMessage());
			alert.showAndWait();
		}
		
	}

	@FXML
	void onviewOnlineReportButton(ActionEvent event) {

	}

	public VirusTotalGuiController() throws IOException {
		FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/GuiFinalView.fxml"));
		loader.setController(this);
		loader.load();
		
		// fix sha256
		viewOnlineReportButton.setDisable(true);
		
		// style
		reportTextArea.setStyle("-fx-font-family: monospace");
		urlReportButton.setStyle("-fx-background-color: #394eff; -fx-text-fill: white;");
		fileReportButton.setStyle("-fx-background-color: #394eff; -fx-text-fill: white;");
		saveReportButton.setStyle("-fx-background-color: #394eff; -fx-text-fill: white;");
	}

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		// TODO Auto-generated method stub
	}

	public BorderPane getView() {
		return view;
	}

}