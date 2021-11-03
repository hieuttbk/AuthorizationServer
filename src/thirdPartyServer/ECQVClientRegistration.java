package thirdPartyServer;

import java.io.BufferedReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
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
 * Servlet implementation class ECQVClientRegistration
 */
@WebServlet("/ECQVClientRegistration")
public class ECQVClientRegistration extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public ECQVClientRegistration() {
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
	    
	    // Retrieve the client identity and the string version of the point U
	    String clientID = jsonReqBody.get("clientID").getAsString();
	    String encodedU = jsonReqBody.get("U").getAsString();
	    
	    System.out.println("ClientID: " + clientID);
	    System.out.println("U value: " + encodedU);
	    
	    /* Create a client table where to store client information if it does not already exist */
	    Connection conn = (Connection) getServletContext().getAttribute("DBConnection");
	    try {
    		// Check if CLIENTS table exists, if not, create a new table
    		DatabaseMetaData dbm = conn.getMetaData();
    		ResultSet rs = dbm.getTables(null, null, "CLIENTS", null);
    		if (rs.next()) {
    			System.out.println("Table CLIENTS already exists in the database");
    		}else {
    			System.out.println("Creating CLIENTS table in the database...");
    			Statement stmt = conn.createStatement();
    			String sql = "CREATE TABLE CLIENTS " +
    					"(id INTEGER AUTO_INCREMENT, " +
    					" client_id VARCHAR(100), " + 
    					" client_q VARCHAR(200), " + 
    					" resource_name VARCHAR(20), " + 
    					" subscription_type VARCHAR(20), " +
    					" PRIMARY KEY ( id ))";
    			stmt.executeUpdate(sql);
    		}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	    /* Perform the neccessary cryptographic operations for the ECQV client registration */
	    String[] data = EllipticCurveCryptography.ECQVRegistration(clientID, encodedU).split("\\|");
	    
	    String cert_u = data[0];
	    String qUser = data[1];
	    String pubKey = data[2];
	    
	    System.out.println("User certificate: " + cert_u);
	    System.out.println("User q value: " + qUser);
	    System.out.println("Public key: " + pubKey);
	    
	    /* Check if the client identifier is already present in the CLIENTS table */
	    boolean exist = false;
	    Statement stmt;
	    String sql1 = "SELECT client_id FROM CLIENTS";
		try {
			stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(sql1);
			while(rs.next()){
				String DBclientID = rs.getString("client_id");
				if(clientID.equals(DBclientID)) {
					exist = true;
				}
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		if(exist) {
			/* Update client_q in the CLIENTS table if the client_id already exist */
			System.out.println("Update the CLIENTS table...");
			String sql2 = "UPDATE CLIENTS SET client_q = ? WHERE client_id = ?";
			try {
				PreparedStatement pstmt = conn.prepareStatement(sql2);
				pstmt.setString(1, qUser);
				pstmt.setString(2, clientID);
				pstmt.executeUpdate();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}else {
			System.out.println("Insert new record in the CLIENTS table");
			/* Insert client_id and client_q in the CLIENTS table */
			String sql3 = "INSERT INTO CLIENTS" +
					"(client_id, client_q) VALUES" +
					"(?, ?)";
			try {
				PreparedStatement pstmt = conn.prepareStatement(sql3);
				pstmt.setString(1, clientID);
				pstmt.setString(2, qUser);
				pstmt.executeUpdate();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	    
	    /* Create the json text to include in the response */
	    JsonObject jsonRespBody = new JsonObject();
		jsonRespBody.addProperty("certificate", cert_u);
		jsonRespBody.addProperty("q", qUser);
		jsonRespBody.addProperty("pubKey", pubKey);
		Gson gson = new GsonBuilder().create();
		String respBody = gson.toJson(jsonRespBody);
		
		System.out.println("Response body: " + respBody);
	    
		response.getWriter().write(respBody);
	    response.setStatus(HttpServletResponse.SC_OK); 
	}

}
