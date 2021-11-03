package thirdPartyServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import thirdPartyServer.ECCsecurity.EllipticCurveCryptography;

/**
 * Servlet implementation class ClientAuthorizationManagement
 */
@WebServlet("/ClientAuthorizationManagement")
public class ClientAuthorizationManagement extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public ClientAuthorizationManagement() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.getWriter().append("Served at: ").append(request.getContextPath());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
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
	    String aeSensorID = jsonReqBody.get("aeID").getAsString();
	    String clientTokenID = jsonReqBody.get("tokenID").getAsString();
	    String Ts = jsonReqBody.get("timestamp").getAsString();
	    
	    System.out.println("AE-ID of the sensor: " + aeSensorID);
	    System.out.println("TokenID assigned to the client: " + clientTokenID);
	    System.out.println("Timestamp: " + Ts);
	    
	    // Check if the tokenID exist in the ACCESS_TOKEN table
	    boolean exist = false;
	    Connection conn = (Connection) getServletContext().getAttribute("DBConnection");
	    Statement stmt;
	    String sql = "SELECT token_id FROM ACCESS_TOKEN";
		try {
			stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(sql);
			while(rs.next()){
				String DBtokenID = rs.getString("token_id");
				if(clientTokenID.equals(DBtokenID)) {
					exist = true;
				}
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		// Before updating the ACCESS_TOKEN, verify that the selected token is not expired
		boolean expired = false;
		sql = "SELECT not_after FROM ACCESS_TOKEN WHERE token_id = ?";
		try {
			java.sql.Date notAfter = null;
			PreparedStatement pstmt = conn.prepareStatement(sql);
			pstmt.setString(1, clientTokenID);
			ResultSet rs = pstmt.executeQuery();
			while(rs.next()){
				notAfter = rs.getDate("not_after");
			}
			// Get the current date
			java.util.Date date = new java.util.Date();
			long now = date.getTime();
			java.sql.Date currentDate = new java.sql.Date(now);
			int result = currentDate.compareTo(notAfter);
			if(result>0) {
				System.out.println("Token has expired!");
				expired = true;
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
					
		// If the tokenID exists in the ACCESS_TOKEN table, than it updates the issuer value with the identifier of
		// the application entity of the sensor measuring the requested resource
		if(exist && !expired) {			
			System.out.println("Update the ACCESS_TOKEN table...");
			sql = "UPDATE ACCESS_TOKEN SET issuer = ? WHERE token_id = ?";
			try {
				PreparedStatement pstmt = conn.prepareStatement(sql);
				pstmt.setString(1, aeSensorID);
				pstmt.setString(2, clientTokenID);
				pstmt.executeUpdate();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			// Get clientID associated with the tokenID from the ACCESS_TOKEN table
			String clientID = null;
			sql = "SELECT audience FROM ACCESS_TOKEN WHERE token_id = ?";
			PreparedStatement pstmt;
			try {
				pstmt = conn.prepareStatement(sql);
				pstmt.setString(1, clientTokenID);
				ResultSet rs = pstmt.executeQuery();
				while(rs.next()){
					clientID = rs.getString("audience");
				}
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			// Generate the session key to return to the OM2M server over the secure channel
			String sessionKey = EllipticCurveCryptography.createSessionKey(clientID, Ts);
			/* Create the json text to include in the response */
		    JsonObject jsonRespBody = new JsonObject();
			jsonRespBody.addProperty("sessionKey", sessionKey);
			Gson gson = new GsonBuilder().create();
			String respBody = gson.toJson(jsonRespBody);
			
			System.out.println("Response body: " + respBody);
		    
			response.getWriter().write(respBody);
		    response.setStatus(HttpServletResponse.SC_OK); 
			
		}else {
			// Stop the registration sending a response back to the client
			response.getWriter().write("Token Id is not present in the table or it has expired!");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		}
		
	    
	}

}
