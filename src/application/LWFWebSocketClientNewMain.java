package application;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.WebSocket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.net.http.HttpClient;
import org.json.*;

public class LWFWebSocketClientNewMain {

	public static String webSocketConnectionString = "";
	private static String webAPIUrl = "http://20.86.77.100/webapi/api/Pipelines/";
	public static Logger logger = Logger.getLogger("application");
	public static boolean isTraceMode = false;

	private static String parseData(JSONObject jsonData) throws InterruptedException, URISyntaxException, IOException {

		logger.log(Level.INFO, "SendDataToWebAPI func: jsonData is: " + jsonData);

		int AlertID = jsonData.getInt("id");
		JSONObject jsonDataInternal = jsonData.getJSONObject("internal");
		JSONObject jsonDataDetails = jsonDataInternal.getJSONObject("details");
		int SerialNumber = jsonDataDetails.getInt("fibre_line_id");
		String AlertName = jsonData.getString("alert_type");
		ColorAlertEnum color = ColorAlertEnum.valueOf(jsonDataInternal.getString("threat_level"));
		int Severity = color.getVal();
		String TimeStamp = jsonData.getString("time");
		float Latitude = jsonDataInternal.getFloat("latitude");
		float Longitude = jsonDataInternal.getFloat("longitude");
		int AlertStatus = jsonData.getInt("resolved_flag");

		// form parameters
		Map<Object, Object> data = new HashMap<>();
		data.put("AlertID", AlertID);
		data.put("SerialNumber", SerialNumber);
		data.put("AlertName", AlertName);
		data.put("Severity", Severity);
		data.put("TimeStamp", TimeStamp);
		data.put("Latitude", Latitude);
		data.put("Longitude", Longitude);
		data.put("AlertStatus", AlertStatus);

		var dataToReturn = buildFormDataFromMap(data);
		logger.log(Level.FINEST, "parseData func: data for send data requset to webApi" + dataToReturn);
		return dataToReturn;
	}

	private static String buildFormDataFromMap(Map<Object, Object> data) {
		var builder = new StringBuilder();
		for (Map.Entry<Object, Object> entry : data.entrySet()) {
			if (builder.length() > 0) {
				builder.append("&");
			}
			builder.append(entry.getKey());
			builder.append("=");
			builder.append(entry.getValue().toString());
		}
		logger.log(Level.FINEST, "buildFormDataFromMap: return string" + builder.toString());
		return builder.toString();
	}

	public static void sendPostRequest(String endpoint, String dataToSend) {
		HttpURLConnection connection = null;

		try {
			URL url = new URL(endpoint);
			connection = (HttpURLConnection) url.openConnection();
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Accept", "application/json");
			connection.setRequestProperty("Content-Type", "application/json");
			connection.setDoOutput(true);
			String strToSend = "\"" + dataToSend + "\"";
			logger.log(Level.FINEST, "sendPostRequest func body data to send" + strToSend);
			OutputStream os = connection.getOutputStream();
			os.write(strToSend.toString().getBytes());
			os.flush();
			os.close();

			var responseCode = connection.getResponseCode();

			if (responseCode != HttpURLConnection.HTTP_OK) {
				logger.log(Level.SEVERE, "sendPostRequest func HTTP error code:" + connection.getResponseCode());
				throw new RuntimeException("Failed : HTTP error code : " + connection.getResponseCode());
			}
			if (responseCode == HttpURLConnection.HTTP_OK) {
				logger.log(Level.FINEST, "POST request success: " + responseCode);
				String line;
				BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
				while ((line = br.readLine()) != null) {
					logger.log(Level.FINEST, "sendPostRequest func respose data" + line);
				}
			} else {
				logger.log(Level.SEVERE, "Faild to send request to WebAPI");
			}

		} catch (IOException e) {
			logger.log(Level.FINEST, "Faild to send request to WebAPI: " + e.getMessage());
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	private static void WebSocketConnect() throws InterruptedException {
		try {
			WebSocket ws = HttpClient.newHttpClient().newWebSocketBuilder()
					.buildAsync(URI.create(webSocketConnectionString), new WebSocketClient()).join();
			logger.log(Level.FINEST, "The websocket requset is: " + ws);
			while (true) {
			}

		} catch (Exception e) {
			logger.log(Level.SEVERE, "Unable to connect to WebSocket Server: " + webSocketConnectionString);
		} finally {
			Thread.sleep(1000);
			if (webSocketConnectionString != "") {
				WebSocketConnect();
			}

		}
	}

	public static class WebSocketClient implements WebSocket.Listener {

		// When a web socket connection is successfully established.
		public void onOpen(WebSocket webSocket) {
			WebSocket.Listener.super.onOpen(webSocket);
			logger.log(Level.FINEST, "listener class WebSocketClient: onOpen func");
		}

		/*
		 * when a text message is received over the web socket connection. It is
		 * triggered whenever the server sends a text message to the client.
		 */
		public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
			getTraceMode();
			logger.log(Level.FINEST, "class WebSocketClient  CompletionStage: onText func" + " webSocket: " + webSocket
					+ " CharSequence: " + data + " boolean: " + last);
			String uniqId = data.toString();
			try {

				JSONObject jsonData = new JSONObject(uniqId);
				String type = GetMessageType(jsonData);
				String time = GetMessageTime(jsonData);
				logger.log(Level.FINEST, "Received message: " + time + " , " + type);

				if (type.equals("Register")) {
					SendFilter(webSocket, uniqId);
					logger.log(Level.FINEST,
							"class WebSocketClient CompletionStage: send data for filter alerts SendFilter func (alert type: Register)");
				}
				if (type.equals("Alert")) {
					var dataToSend = parseData(jsonData);
					sendPostRequest(webAPIUrl + "PostPipelineAlert", dataToSend);
					logger.log(Level.FINEST,
							"class WebSocketClient CompletionStage: send data for insert to DB SendDataToWebAPI func (alert type: Alert)");
				}

			} catch (Exception e) {
				logger.log(Level.SEVERE, "class WebSocketClient CompletionStage : Wrong alert " + e.getMessage());
			}

			logger.log(Level.FINEST, "onText received: " + data);
			return WebSocket.Listener.super.onText(webSocket, data, last);

		}

		// When the connection is lost, here we try connect again to server.
		public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
			try {
				webSocketConnectionString = getWebSocketConnectionString();
				if (!webSocketConnectionString.equals("")) {
					try {
						WebSocketConnect();
					} catch (Exception e) {
						logger.log(Level.WARNING, "onError Exception: " + e.getMessage());
					}
				}
			} catch (Exception e) {
				logger.log(Level.WARNING, "onClose Exception: " + e.getMessage());
			}
			return WebSocket.Listener.super.onClose(webSocket, statusCode, reason);
		}

		/*
		 * To handle unexpected exceptions or errors that occur during the lifecycle of
		 * the web socket connection, such as errors during message transmission,
		 * parsing, or encoding/decoding.
		 */
		public void onError(WebSocket webSocket, Throwable error) {
			logger.log(Level.WARNING, "Connection is lost! " + webSocket.toString() + " error " + error);
			try {
				webSocketConnectionString = getWebSocketConnectionString();
			} catch (IOException e) {
				logger.log(Level.WARNING, "onError Exception try to get webSocketConnectionString : " + e.getMessage());
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (!webSocketConnectionString.equals("")) {
				try {
					WebSocketConnect();
				} catch (Exception e) {
					logger.log(Level.WARNING, "onError Exception: " + e.getMessage());
				}
			}
			WebSocket.Listener.super.onError(webSocket, error);
		}

	}

	public static String GetMessageType(JSONObject jsonData) {
		if (jsonData != null) {
			logger.log(Level.FINEST, "GetAlertType: " + jsonData);
			return jsonData.getString("object_type");
		} else {
			logger.log(Level.WARNING, "GetAlertType: jsonData was recived null");
			return "";
		}
	}

	public static String GetMessageTime(JSONObject jsonData) {
		if (jsonData != null) {
			logger.log(Level.FINEST, "GetAlertType: " + jsonData);
			return jsonData.getString("time");
		} else {
			logger.log(Level.WARNING, "GetAlertType: jsonData was recived null");
			return "";
		}
	}

	public static void SendFilter(WebSocket webSocket, String data) {
		logger.log(Level.FINEST, "SendFilter func: " + "webSocket " + webSocket + " data" + data);
		try {
			String[] str = data.split(":");
			String temp = str[4];
			String unique_id = temp.substring(0, temp.length() - 1);
			long myLong = Long.parseLong(unique_id);
			String objectType = "Filter";
			long connectionId = myLong;
			String[] objectTypeFilter = { "Event", "Alert" };
			String jsonStr = String.format(
					"{\"object_type_version\":1,\"object_type\":\"%s\",\"connection_id\":%d,\"object_type_filter\":[\"%s\",\"%s\"]}",
					objectType, connectionId, objectTypeFilter[0], objectTypeFilter[1]);
			webSocket.sendText(jsonStr, true);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "SendFilter func: Exception " + "no data to filter" + e.getMessage());
		}
	}

	public static String getWebSocketConnectionString() throws IOException {
		String uriData = "";
		String port = "";
		String rootPass = "";
		String url = webAPIUrl + "GetLwfwebSocketConnectionData?customerName=Tirana";

		try {
			logger.log(Level.FINEST,
					"getWebSocketConnectionString : trying to send request to WebApi to get connection string");
			URL obj = new URL(url);
			HttpURLConnection con = (HttpURLConnection) obj.openConnection();
			con.setRequestMethod("GET");
			int responseCode = con.getResponseCode();
			logger.log(Level.FINEST, "GET Response Code: " + responseCode);
			if (responseCode == HttpURLConnection.HTTP_OK) {
				// success
				BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
				String inputLine;
				StringBuffer response = new StringBuffer();

				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
				in.close();

				logger.log(Level.FINEST, "getWebSocketConnectionString: " + response.toString());
				var str = response.toString();
				String[] res = str.split(",");
				uriData = res[2].substring(res[2].indexOf(":") + 3, res[2].length() - 1);
				port = res[3].substring(res[3].indexOf(":") + 2);
				rootPass = res[4].substring(res[4].indexOf(":") + 4, res[4].length() - 1);
			} else {
				logger.log(Level.SEVERE, "getWebSocketConnectionString faild: GET request did not work");
			}
		} catch (IOException e) {
			logger.log(Level.SEVERE, "getWebSocketConnectionString faild");
		}

		logger.log(Level.FINEST, "getWebSocketConnectionString func ok: " + uriData + ":" + port + "/" + rootPass);
		return (uriData + ":" + port + "/" + rootPass);

	}

	public static boolean getClientModeStatus() {
		String url = webAPIUrl + "GetClientModeStatus?customerName=Tirana";
		try {
			logger.log(Level.FINEST, "getClientModeStatus : trying to send request to WebApi to get connection string");
			URL obj = new URL(url);
			HttpURLConnection con = (HttpURLConnection) obj.openConnection();
			con.setRequestMethod("GET");
			int responseCode = con.getResponseCode();
			logger.log(Level.FINEST, "GET Response Code: " + responseCode);
			if (responseCode == HttpURLConnection.HTTP_OK) {
				// success
				BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
				String inputLine;
				StringBuffer response = new StringBuffer();

				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
				in.close();

				logger.log(Level.FINEST, "getClientModeStatus Trace mode response is: " + response.toString());
				var strToConvert = response.toString();
				isTraceMode = Boolean.parseBoolean(strToConvert);
				return isTraceMode;
			} else {
				logger.log(Level.SEVERE, "getWebSocketConnectionString faild: GET request did not work");
			}
		} catch (IOException e) {
			logger.log(Level.SEVERE, "getClientModeStatus faild");
		}
		return isTraceMode;
	}

	public static void getTraceMode() {
		isTraceMode = getClientModeStatus();
		logger.log(Level.INFO, "Trace mode: {0}", isTraceMode);
		if (isTraceMode) {
			logger.setLevel(Level.FINEST);
		} else {
			logger.setLevel(Level.WARNING);
		}
	}

	public static void main(String[] args) throws InterruptedException, SecurityException, IOException {
		try {
			getTraceMode();
			webSocketConnectionString = getWebSocketConnectionString();
			if (!webSocketConnectionString.equals("")) {
				logger.log(Level.FINEST, "The webSocketConnectionString is: " + webSocketConnectionString);
				try {
					WebSocketConnect();
				} catch (InterruptedException e) {
					throw new RuntimeException(e);
				}
			} else {
				logger.log(Level.WARNING, "The webSocketConnectionString is null");
			}
		} catch (IOException ex) {
			logger.log(Level.SEVERE, "check webSocket connection string");
		}
	}
}
