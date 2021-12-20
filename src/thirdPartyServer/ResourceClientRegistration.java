package thirdPartyServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Calendar;
import java.util.Random;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.math.ec.ECPoint;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import thirdPartyServer.ECCsecurity.EllipticCurveCryptography;
import thirdPartyServer.util.SSLSocketGenerator;
import thirdPartyServer.util.ServerConstants;

/**
 * Servlet implementation class ResourceClientRegistration
 */
@WebServlet("/ResourceClientRegistration")
public class ResourceClientRegistration extends HttpServlet {
	private static final long serialVersionUID = 1L;

	// Address and port where the OM2M IPE is listening
	private String host = "127.0.0.1";
	private int port = 10000;

	// Provide security information for apache https client that needs to
	// communicate with the OM2M server
	private static final String KEY_STORE_LOCATION = "/home/simone/eclipse-workspace-webApp-TTP/AuthorizationServer/certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "/home/simone/eclipse-workspace-webApp-TTP/AuthorizationServer/certs/trustStore.jks";

	private static final String ALIAS = "das";

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	private static byte[] longToByteArray(long value) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(value);
		return buffer.array();

	}

	public ResourceClientRegistration() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.getWriter().append("Served at: ").append(request.getContextPath());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// Message to provide extra info to the client
		String msgInfo = null;
		/* Retrieve the content of the client request */
		BufferedReader reader = request.getReader();
		StringBuilder sb = new StringBuilder();
		String line = reader.readLine();
		while (line != null) {
			sb.append(line + "\n");
			line = reader.readLine();
		}
		reader.close();
		String body = sb.toString();

		// Parse the json payload
		JsonParser parser = new JsonParser();
		JsonObject jsonReqBody = parser.parse(body).getAsJsonObject();

		// Retrieve clientID, timestamp, subscription and nonce
		// String clientID = jsonReqBody.get("clientID").getAsString();
		String Tr = jsonReqBody.get("timestamp").getAsString();
		String sub = jsonReqBody.get("subscription").getAsString();
		String nonce = jsonReqBody.get("nonce").getAsString();
		String encodeZ = jsonReqBody.get("encodeZ").getAsString();

		// System.out.println("Client ID: " + clientID);
		System.out.println("Timestamp Tr: " + Tr);
		System.out.println("Subscription: " + sub);
		System.out.println("Nonce: " + nonce);
		System.out.println("EncodeZ: " + encodeZ);

		// Decrypt the application specific data and the random number c
		String[] dataReq = EllipticCurveCryptography.resourceRegistrationReq(Tr, sub, nonce, encodeZ).split("\\|");

		String reqResName = dataReq[0];
		String reqSubType = dataReq[1];
		String c = dataReq[2];
		String clientID = dataReq[3];
		String Kr = dataReq[4];

		// Check if the client has already passed the ECQV registration
		Connection conn = (Connection) getServletContext().getAttribute("DBConnection");
		// Check if the client identifier is already present in the CLIENTS table
		boolean exist = checkClientIDpresenceInCLIENTS(conn, clientID);

		if (!exist) {
			// Stop the registration sending a response back to the client
			response.getWriter().write("Client didn't execute the ECQV registration with the dynamic authorization "
					+ "server.\n Stop connection!!");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		} else {
			/*
			 * // Decrypt the application specific data and the random number c String[]
			 * dataReq = EllipticCurveCryptography.resourceRegistrationReq(clientID, Tr,
			 * sub, nonce).split("\\|"); String reqResName = dataReq[0]; String reqSubType =
			 * dataReq[1]; String c = dataReq[2];
			 */

			// Validity days and costs according to the requested subscription type
			int days = 0;
			int cost = 0;
			if (reqSubType.equals(ServerConstants.SILVER)) {
				days = ServerConstants.SILVER_PERIOD;
				cost = ServerConstants.SILVER_COST;
			} else if (reqSubType.equals(ServerConstants.GOLD)) {
				days = ServerConstants.GOLD_PERIOD;
				cost = ServerConstants.GOLD_COST;
			} else if (reqSubType.equals(ServerConstants.PLATINUM)) {
				days = ServerConstants.PLATINUM_PERIOD;
				cost = ServerConstants.PLATINUM_COST;
			}

			// Check if the client is already registered in the CLIENTS table for the
			// requested resource
			String resNameRegCLIENTS = retrieveResNameInCLIENTS(conn, clientID, reqResName);
			if (resNameRegCLIENTS == null) {
				// Update the corresponding record in the CLIENTS table
				updateCLIENTSwithResNameAndSubType(conn, clientID, reqResName, reqSubType);
			} else {
				if (resNameRegCLIENTS.equals(reqResName)) {
					// Update the record with the new subscription type information in the CLIENTS
					// table
					updateCLIENTSwithNewSubType(conn, clientID, reqResName, reqSubType);
				} else {
					// Insert new record with the requested resource name and subscription type in
					// the CLIENTS table
					insertCLIENTSwithReqResNameAndReqSubType(conn, clientID, reqResName, reqSubType);
				}
			}

			// Check if the combination reqResName-reqSubType is present in one record of
			// ACCESS_TOKEN
			boolean combExist = checkResNameSubTypePresenceInACCESS_TOKENS(conn, reqResName, reqSubType);
			if (!combExist) {
				response.getWriter().write("Invalid combination of resource name and subscription type!!");
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			} else {
				// check If Kr respone == kr DAS created
				System.out.println("\n >>>>>>> Process 6.9 check Kr = H(k*Pu||Tr) .....");
				String KrByDAS = EllipticCurveCryptography.CreatedKr(clientID, Tr);
				if (Kr.equals(KrByDAS)) {
					System.out.println("Check Kr is succesful! ");

					// If the combination reqResName-reqSubType exists, then retrieve the tokenID
					// corresponding to
					// the clientID as audience in ACCESS_TOKEN
					String tokenID = retrieveTokenIDinACCESS_TOKEN(conn, clientID, reqResName, reqSubType);
					// If tokenID == null, then we need to retrieve the audience corresponding to
					// the requested combination
					// of resource name and subscription type from the table ACCESS_TOKEN
					if (tokenID == null) {
						String audience = retrieveAudienceInACCESS_TOKEN(conn, reqResName, reqSubType);
						// If audience == null, then this is the first client interested in the
						// requested
						// combination of resource name and subscription type in the table ACCESS_TOKEN

						// Compute the current date for the access token
						java.util.Date date = new java.util.Date();
						long now = date.getTime();
						java.sql.Date notBefore = new java.sql.Date(now);
						System.out.println("SQL start data: " + notBefore.toString());
						// Compute the expiration date for the access token
						Calendar cal = Calendar.getInstance();
						cal.setTime(notBefore);
						cal.add(Calendar.DATE, days);
						java.sql.Date notAfter = new java.sql.Date(cal.getTimeInMillis());
						System.out.println("SQL end data: " + notAfter.toString());
						if (audience == null) {
							// Check if the client has already a different subscription for the same
							// resource name by retrieving
							// the tokenID
							String alreadySubTokenID = checkClientIDsubscriptionInACCESS_TOKEN(conn, clientID,
									reqResName);
							if (alreadySubTokenID != null) {
								// Delete issuer, not_before, not_after, audience corresponding to the retrieved
								// tokenID in the
								// table ACCESS_TOKEN
								deleteFieldsCorrespondingToTokenIDinACCESS_TOKEN(conn, alreadySubTokenID);
							}
							// Update the record corresponding to the requested resource name and
							// subscription type in
							// the table ACCESS_TOKEN by setting audience, not_before and note_after.
							updateACCESS_TOKENwithNotBeforeNotAfterAudience(conn, notBefore, notAfter, clientID,
									reqResName, reqSubType);
						} else {
							// The requested token is already in use by another client, therefore we need to
							// create
							// another token in the table ACCESS_TOKEN with different token_id and audience
							// parameter.
							// Compute the new tokenID to insert in the table ACCESS_TOKEN
							Random rnd = new Random();
							tokenID = "T" + Integer.toString(rnd.nextInt(0X1000000), 16);
							insertACCESS_TOKEN(conn, tokenID, notBefore, notAfter, reqResName, clientID, reqSubType,
									cost, days);
						}
					} else {
						// If tokenID != null for the client, then retrieve its expiration date from the
						// table ACCESS_TOKEN
						// to verify if it is still valid
						java.sql.Date expirationDate = retrieveNotAfterFromACCESS_TOKEN(conn, tokenID);
						// Compute current date
						java.util.Date newDate = new java.util.Date();
						long newTime = newDate.getTime();
						java.sql.Date currentDate = new java.sql.Date(newTime);
						if (currentDate.before(expirationDate)) {
							msgInfo = "The client has already an access token for the requested resource"
									+ " name and subscription type!!";
							/*
							 * response.getWriter().
							 * write("The client has already an access token for the requested resource" +
							 * " name and subscription type!!");
							 */
						} else {
							// Update the record corresponding to the tokenID with the new validity period
							// in the table ACCESS_TOKEN.

							// Compute the current date for the access token
							java.util.Date date = new java.util.Date();
							long now = date.getTime();
							java.sql.Date notBefore = new java.sql.Date(now);
							System.out.println("SQL start data: " + notBefore.toString());
							// Compute the expiration date for the access token
							Calendar cal = Calendar.getInstance();
							cal.setTime(notBefore);
							cal.add(Calendar.DATE, days);
							java.sql.Date notAfter = new java.sql.Date(cal.getTimeInMillis());
							System.out.println("SQL end data: " + notAfter.toString());

							updateACCESS_TOKENwithNotBeforeAndNotAfter(conn, tokenID, notBefore, notAfter);
						}
					}

					// Retrieve the tokenID from the table ACCESS_TOKEN
					String DBtokenID = retrieveTokenIDinACCESS_TOKEN(conn, clientID, reqResName, reqSubType);
					//String Texp= retrieveTexpinACCESS_TOKEN(conn, clientID, reqResName, reqSubType);
					
					

					// Retrieve the parameter not_after from the table ACCESS_TOKEN
					//java.sql.Date notAfter = retrieveNotAfterFromACCESS_TOKEN(conn, DBtokenID);
					
					// String Texp= retrieveTexpinACCESS_TOKEN(conn, clientID, reqResName,
					// reqSubType);

					// Retrieve the parameter not_after from the table ACCESS_TOKEN
					java.sql.Date notAfter = retrieveNotAfterFromACCESS_TOKEN(conn, DBtokenID);
					// String Texp= notAfter.toString();

					String Texp = notAfter.toString();
					// Generate the key Kt and the Ticket
					String[] dataResp = EllipticCurveCryptography
							.resourceRegistrationResp(clientID, DBtokenID, reqResName, c, Kr, Texp).split("\\|");
					String ET = dataResp[0];
					String Kt = dataResp[1];
					String n1 = dataResp[2];
					String n2 = dataResp[3];

					// Prepare the response with the ticket to be sent to the client
					JsonObject jsonRespBody = new JsonObject();
					jsonRespBody.addProperty("ET", ET);
					jsonRespBody.addProperty("nonce2", n2);
					jsonRespBody.addProperty("nonce1", n1);
					if (msgInfo != null) {
						jsonRespBody.addProperty("message", msgInfo);
					}
					Gson gson = new GsonBuilder().create();
					String respBody = gson.toJson(jsonRespBody);

					System.out.println("Response body: " + respBody);

					// Prepare the https request to send security credentials to the OM2M IPE in
					// order to be able
					// to authenticate the client (Use the javax.net.ssl).

					// Create the json body for the request
					JsonObject jsonReqOM2M = new JsonObject();
					jsonReqOM2M.addProperty("symmetricKey", Kt);
					jsonReqOM2M.addProperty("nonce1", n1);
					jsonReqOM2M.addProperty("random", c);
					jsonReqOM2M.addProperty("Texp", notAfter.toString());
					String reqOM2MBody = gson.toJson(jsonReqOM2M);
					System.out.println("Send credentials: " + reqOM2MBody);

					// Create the SSLSocketFactory with keystore and truststore
					httpsRun(reqOM2MBody);

					// Send the ticket back to the client
					if (response.getStatus() != HttpServletResponse.SC_BAD_REQUEST
							&& response.getStatus() != HttpServletResponse.SC_UNAUTHORIZED) {
						response.getWriter().write(respBody);
						response.setStatus(HttpServletResponse.SC_OK);
					}
				} else {
					System.out.println("Check Kr is fail! ");
				}
//				// If the combination reqResName-reqSubType exists, then retrieve the tokenID
//				// corresponding to
//				// the clientID as audience in ACCESS_TOKEN
//				String tokenID = retrieveTokenIDinACCESS_TOKEN(conn, clientID, reqResName, reqSubType);
//				// If tokenID == null, then we need to retrieve the audience corresponding to
//				// the requested combination
//				// of resource name and subscription type from the table ACCESS_TOKEN
//				if (tokenID == null) {
//					String audience = retrieveAudienceInACCESS_TOKEN(conn, reqResName, reqSubType);
//					// If audience == null, then this is the first client interested in the
//					// requested
//					// combination of resource name and subscription type in the table ACCESS_TOKEN
//
//					// Compute the current date for the access token
//					java.util.Date date = new java.util.Date();
//					long now = date.getTime();
//					java.sql.Date notBefore = new java.sql.Date(now);
//					System.out.println("SQL start data: " + notBefore.toString());
//					// Compute the expiration date for the access token
//					Calendar cal = Calendar.getInstance();
//					cal.setTime(notBefore);
//					cal.add(Calendar.DATE, days);
//					java.sql.Date notAfter = new java.sql.Date(cal.getTimeInMillis());
//					System.out.println("SQL end data: " + notAfter.toString());
//					if (audience == null) {
//						// Check if the client has already a different subscription for the same
//						// resource name by retrieving
//						// the tokenID
//						String alreadySubTokenID = checkClientIDsubscriptionInACCESS_TOKEN(conn, clientID, reqResName);
//						if (alreadySubTokenID != null) {
//							// Delete issuer, not_before, not_after, audience corresponding to the retrieved
//							// tokenID in the
//							// table ACCESS_TOKEN
//							deleteFieldsCorrespondingToTokenIDinACCESS_TOKEN(conn, alreadySubTokenID);
//						}
//						// Update the record corresponding to the requested resource name and
//						// subscription type in
//						// the table ACCESS_TOKEN by setting audience, not_before and note_after.
//						updateACCESS_TOKENwithNotBeforeNotAfterAudience(conn, notBefore, notAfter, clientID, reqResName,
//								reqSubType);
//					} else {
//						// The requested token is already in use by another client, therefore we need to
//						// create
//						// another token in the table ACCESS_TOKEN with different token_id and audience
//						// parameter.
//						// Compute the new tokenID to insert in the table ACCESS_TOKEN
//						Random rnd = new Random();
//						tokenID = "T" + Integer.toString(rnd.nextInt(0X1000000), 16);
//						insertACCESS_TOKEN(conn, tokenID, notBefore, notAfter, reqResName, clientID, reqSubType, cost,
//								days);
//					}
//				} else {
//					// If tokenID != null for the client, then retrieve its expiration date from the
//					// table ACCESS_TOKEN
//					// to verify if it is still valid
//					java.sql.Date expirationDate = retrieveNotAfterFromACCESS_TOKEN(conn, tokenID);
//					// Compute current date
//					java.util.Date newDate = new java.util.Date();
//					long newTime = newDate.getTime();
//					java.sql.Date currentDate = new java.sql.Date(newTime);
//					if (currentDate.before(expirationDate)) {
//						msgInfo = "The client has already an access token for the requested resource"
//								+ " name and subscription type!!";
//						/*
//						 * response.getWriter().
//						 * write("The client has already an access token for the requested resource" +
//						 * " name and subscription type!!");
//						 */
//					} else {
//						// Update the record corresponding to the tokenID with the new validity period
//						// in the table ACCESS_TOKEN.
//
//						// Compute the current date for the access token
//						java.util.Date date = new java.util.Date();
//						long now = date.getTime();
//						java.sql.Date notBefore = new java.sql.Date(now);
//						System.out.println("SQL start data: " + notBefore.toString());
//						// Compute the expiration date for the access token
//						Calendar cal = Calendar.getInstance();
//						cal.setTime(notBefore);
//						cal.add(Calendar.DATE, days);
//						java.sql.Date notAfter = new java.sql.Date(cal.getTimeInMillis());
//						System.out.println("SQL end data: " + notAfter.toString());
//
//						updateACCESS_TOKENwithNotBeforeAndNotAfter(conn, tokenID, notBefore, notAfter);
//					}
//				}
//
//				// Retrieve the tokenID from the table ACCESS_TOKEN
//				String DBtokenID = retrieveTokenIDinACCESS_TOKEN(conn, clientID, reqResName, reqSubType);
//				// Retrieve the parameter not_after from the table ACCESS_TOKEN
//				java.sql.Date notAfter = retrieveNotAfterFromACCESS_TOKEN(conn, DBtokenID);
//				// Generate the key Kt and the Ticket
//				String[] dataResp = EllipticCurveCryptography.resourceRegistrationResp(clientID, DBtokenID, reqResName)
//						.split("\\|");
//				String ticket = dataResp[0];
//				String Kt = dataResp[1];
//				String n = dataResp[2];
//
//				// Prepare the response with the ticket to be sent to the client
//				JsonObject jsonRespBody = new JsonObject();
//				jsonRespBody.addProperty("ticket", ticket);
//				if (msgInfo != null) {
//					jsonRespBody.addProperty("message", msgInfo);
//				}
//				Gson gson = new GsonBuilder().create();
//				String respBody = gson.toJson(jsonRespBody);
//
//				System.out.println("Response body: " + respBody);
//
//				// Prepare the https request to send security credentials to the OM2M IPE in
//				// order to be able
//				// to authenticate the client (Use the javax.net.ssl).
//
//				// Create the json body for the request
//				JsonObject jsonReqOM2M = new JsonObject();
//				jsonReqOM2M.addProperty("symmetricKey", Kt);
//				jsonReqOM2M.addProperty("nonce", n);
//				jsonReqOM2M.addProperty("random", c);
//				jsonReqOM2M.addProperty("Texp", notAfter.toString());
//				String reqOM2MBody = gson.toJson(jsonReqOM2M);
//				System.out.println("Send credentials: " + reqOM2MBody);
//
//				// Create the SSLSocketFactory with keystore and truststore
//				httpsRun(reqOM2MBody);
//
//				// Send the ticket back to the client
//				if (response.getStatus() != HttpServletResponse.SC_BAD_REQUEST
//						&& response.getStatus() != HttpServletResponse.SC_UNAUTHORIZED) {
//					response.getWriter().write(respBody);
//					response.setStatus(HttpServletResponse.SC_OK);
//				}
			}
		}
	}

	// Check client_ID existence in the CLIENTS table
	public boolean checkClientIDpresenceInCLIENTS(Connection conn, String clientID) {
		boolean exist = false;
		System.out.println("Checking client_ID existence in the CLIENTS table...");
		String sql = "SELECT client_id FROM CLIENTS";
		try {
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(sql);
			while (rs.next()) {
				String DBclientID = rs.getString("client_id");
				if (clientID.equals(DBclientID)) {
					exist = true;
				}
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return exist;
	}

	// Retrieve the requested resource for the specific client in the CLIENTS table
	public String retrieveResNameInCLIENTS(Connection conn, String clientID, String reqResName) {
		String CLIENTSDBresName = null;
		System.out.println("Checking resource existence for client in the CLIENTS table...");
		String sql = "SELECT resource_name FROM CLIENTS WHERE client_id = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, clientID);
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				CLIENTSDBresName = rs.getString("resource_name");
				if (reqResName.equals(CLIENTSDBresName)) {
					break;
				}
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return CLIENTSDBresName;
	}

	// Update the CLIENTS table with the requested resource name and subscription
	// type
	public void updateCLIENTSwithResNameAndSubType(Connection conn, String clientID, String reqResName,
			String reqSubType) {
		System.out.println("Update the CLIENTS table with requested resource name and subscription type...");
		String sql = "UPDATE CLIENTS SET resource_name = ?, subscription_type = ? WHERE client_id = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, reqResName);
			pstmt.setString(2, reqSubType);
			pstmt.setString(3, clientID);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// Update the CLIENTS table with the new subscription type
	public void updateCLIENTSwithNewSubType(Connection conn, String clientID, String reqResName, String reqSubType) {
		System.out
				.println("Update the CLIENTS table with new subscription type for specific client_id and resource...");
		String sql = "UPDATE CLIENTS SET subscription_type = ? WHERE client_id = ? AND resource_name = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, reqSubType);
			pstmt.setString(2, clientID);
			pstmt.setString(3, reqResName);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// Insert new record with the requested resource name and subscription type in
	// the CLIENTS table
	public void insertCLIENTSwithReqResNameAndReqSubType(Connection conn, String clientID, String reqResName,
			String reqSubType) {
		String clientq = EllipticCurveCryptography.getClientIDandq().get(clientID);
		System.out.println("Create record in the CLIENTS table...");
		String sql = "INSERT INTO CLIENTS" + "(client_id, client_q, resource_name, subscription_type) VALUES"
				+ "(?, ?, ?, ?)";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, clientID);
			pstmt.setString(2, clientq);
			pstmt.setString(3, reqResName);
			pstmt.setString(4, reqSubType);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// Check if the requested combination resource name - subscription type is
	// present in at least one record
	// of the table ACCESS_TOKEN
	public boolean checkResNameSubTypePresenceInACCESS_TOKENS(Connection conn, String reqResName, String reqSubType) {
		boolean combExist = false;
		System.out.println("Checking presence of requested combination of resource name and subscription type "
				+ "in the ACCESS_TOKEN table...");
		String sql = "SELECT token_name, sub_type FROM ACCESS_TOKEN";
		try {
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(sql);
			while (rs.next()) {
				String tok_name = rs.getString("token_name");
				String sub_type = rs.getString("sub_type");
				if (tok_name.equals(reqResName) && sub_type.equals(reqSubType)) {
					combExist = true;
					break;
				}
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return combExist;
	}

	// Retrieve tokenID corresponding to reqResName, reqSubType and clientID in the
	// table ACCESS_TOKEN
	public String retrieveTokenIDinACCESS_TOKEN(Connection conn, String clientID, String reqResName,
			String reqSubType) {
		String tokenID = null;
		// String Texp = null;
		System.out.println("Retrieving TokenID corresponding to clientID and requested resource name and subscription"
				+ " type from the table ACCESS_TOKEN...");
		String sql = "SELECT token_id FROM ACCESS_TOKEN WHERE token_name = ? AND audience = ? AND sub_type = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, reqResName);
			pstmt.setString(2, clientID);
			pstmt.setString(3, reqSubType);
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				tokenID = rs.getString("token_id");
				// Texp=rs.getString("validity_interval");
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return tokenID;
	}

	public String retrieveTexpinACCESS_TOKEN(Connection conn, String clientID, String reqResName, String reqSubType) {
		String Texp = null;
		// String Texp = null;
		System.out.println("Retrieving Texp corresponding to clientID and requested resource name and subscription"
				+ " type from the table ACCESS_TOKEN...");
		String sql = "SELECT validity_interval FROM ACCESS_TOKEN WHERE token_name = ? AND audience = ? AND sub_type = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, reqResName);
			pstmt.setString(2, clientID);
			pstmt.setString(3, reqSubType);
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				Texp = rs.getString("validity_interval");
				// Texp=rs.getString("validity_interval");
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return Texp;
	}

	// Retrieve audience corresponding to reqResName and reqSubType in the table
	// ACCESS_TOKEN
	public String retrieveAudienceInACCESS_TOKEN(Connection conn, String reqResName, String reqSubType) {
		String audience = null;
		System.out.println("Retrieving audience corresponding to the requested resource name and subscription"
				+ " type from the table ACCESS_TOKEN...");
		String sql = "SELECT audience FROM ACCESS_TOKEN WHERE token_name = ? AND sub_type = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, reqResName);
			pstmt.setString(2, reqSubType);
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				audience = rs.getString("audience");
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return audience;
	}

	// Update the record corresponding to reqResName and reqSubType in the table
	// ACCESS_TOKEN to bind the client
	// with a specific access token
	public void updateACCESS_TOKENwithNotBeforeNotAfterAudience(Connection conn, java.sql.Date notBefore,
			java.sql.Date notAfter, String clientID, String reqResName, String reqSubType) {
		System.out.println("Updating the ACCESS_TOKEN table with start and end subscription time and audience...");
		String sql = "UPDATE ACCESS_TOKEN SET not_before = ?, not_after = ?, audience = ? "
				+ "WHERE token_name = ? AND sub_type = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setDate(1, notBefore);
			pstmt.setDate(2, notAfter);
			pstmt.setString(3, clientID);
			pstmt.setString(4, reqResName);
			pstmt.setString(5, reqSubType);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// Insert new token in the table ACCESS_TOKEN
	public void insertACCESS_TOKEN(Connection conn, String tokenID, java.sql.Date notBefore, java.sql.Date notAfter,
			String tokenName, String audience, String subType, int cost, int validityInterval) {
		System.out.println("Create record in the ACCESS_TOKEN table...");
		String sql = "INSERT INTO ACCESS_TOKEN (token_id, holder, not_before, not_after, token_name, audience, "
				+ "permission, sub_type, cost, validity_interval) VALUES" + "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, tokenID);
			pstmt.setString(2, ServerConstants.HOLDER);
			pstmt.setDate(3, notBefore);
			pstmt.setDate(4, notAfter);
			pstmt.setString(5, tokenName);
			pstmt.setString(6, audience);
			pstmt.setInt(7, ServerConstants.RETRIEVE);
			pstmt.setString(8, subType);
			pstmt.setInt(9, cost);
			pstmt.setInt(10, validityInterval);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// Retrieve the not_after parameter corresponding to the tokenID from the table
	// ACCESS_TOKEN
	public java.sql.Date retrieveNotAfterFromACCESS_TOKEN(Connection conn, String tokenID) {
		java.sql.Date notAfter = null;
		System.out.println("Retrieve not_after corresponding to the token_id from the ACCESS_TOKEN table...");
		String sql = "SELECT not_after FROM ACCESS_TOKEN WHERE token_id = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, tokenID);
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				notAfter = rs.getDate("not_after");
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return notAfter;
	}

	// Update the record corresponding to the tokenID with the new values for
	// not_before and not_after in the table
	// ACCESS_TOKEN
	public void updateACCESS_TOKENwithNotBeforeAndNotAfter(Connection conn, String tokenID, java.sql.Date notBefore,
			java.sql.Date notAfter) {
		System.out.println("Updating the ACCESS_TOKEN table with start and end subscription time...");
		String sql = "UPDATE ACCESS_TOKEN SET not_before = ?, not_after = ? WHERE token_id = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setDate(1, notBefore);
			pstmt.setDate(2, notAfter);
			pstmt.setString(3, tokenID);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// Check if the client has already a different subscription type for the same
	// resource in the table ACCESS_TOKEN
	public String checkClientIDsubscriptionInACCESS_TOKEN(Connection conn, String clientID, String reqResName) {
		String tokenID = null;
		System.out.println("Checking if client has already a different subscription for the same resource "
				+ "in the ACCESS_TOKEN table...");
		String sql = "SELECT token_id FROM ACCESS_TOKEN WHERE token_name = ? AND audience = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, reqResName);
			pstmt.setString(2, clientID);
			ResultSet rs = pstmt.executeQuery();
			while (rs.next()) {
				tokenID = rs.getString("token_id");
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return tokenID;
	}

	// Delete the fields issuer, not_before, not_after, audience corresponding to a
	// token_id from the table ACCESS_TOKEN
	public void deleteFieldsCorrespondingToTokenIDinACCESS_TOKEN(Connection conn, String retrievedTokenID) {
		System.out.println("Updating specific record by setting NULL values in the ACCESS_TOKEN table...");
		String sql = "UPDATE ACCESS_TOKEN SET issuer = NULL, not_before = NULL, not_after = NULL,"
				+ " audience = NULL WHERE token_id = ?";
		try {
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, retrievedTokenID);
			pstmt.executeUpdate();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// Start to run the client
	public void httpsRun(String payload) {
		SSLSocketGenerator sslSocketGen = new SSLSocketGenerator(ALIAS, KEY_STORE_LOCATION, TRUST_STORE_LOCATION);
		SSLContext sslContext;

		try {
			sslContext = sslSocketGen.getSSLSocketFactory();
			// Create socket factory
			SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

			// Create socket
			SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(this.host, this.port);

			System.out.println("SSL client started");
			new ClientThread(sslSocket, payload).start();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	// Thread handling the socket to server
	static class ClientThread extends Thread {
		private SSLSocket sslSocket = null;
		private String payload = null;

		ClientThread(SSLSocket sslSocket, String payload) {
			this.sslSocket = sslSocket;
			this.payload = payload;
		}

		public void run() {
			sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

			try {
				// Start handshake
				sslSocket.startHandshake();

				// Get session after the connection is established
				SSLSession sslSession = sslSocket.getSession();

				System.out.println("SSLSession :");
				System.out.println("\tProtocol : " + sslSession.getProtocol());
				System.out.println("\tCipher suite : " + sslSession.getCipherSuite());

				// Start handling application content
				InputStream inputStream = sslSocket.getInputStream();
				OutputStream outputStream = sslSocket.getOutputStream();

				BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
				PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));

				// Write data
				printWriter.println(payload);
				printWriter.flush();

				String line = null;
				while ((line = bufferedReader.readLine()) != null) {
					System.out.println("Input : " + line);

					if (line.trim().equals("HTTP/1.1 200\r\n")) {
						break;
					}
				}

				sslSocket.close();
			} catch (Exception ex) {
				ex.printStackTrace();
			}
		}
	}

}
