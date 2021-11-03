package thirdPartyServer;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Random;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import thirdPartyServer.util.ServerConstants;

/**
 * Servlet implementation class TokenManager
 */
@WebServlet("/TokenManager")
public class TokenManager extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public TokenManager() {
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
		Random rnd;
		String tokNum;
		String tokenID;
		String holder;
		int cost = 0;
		int validityInterval = 0;
		
		String resources = request.getParameter("resources");
		String permission = request.getParameter("permission");
		String subType = request.getParameter("subType");
		String errorMsg = null;
		
		if(resources == null || resources.equals("")) {
			errorMsg = "The name of the resources can't be null or empty.";
		}
		if(permission == null || permission.equals("")) {
			errorMsg = "Access permission can't be null or empty.";
		}
		if(!subType.equals(ServerConstants.SILVER) && !subType.equals(ServerConstants.GOLD) && !subType.equals(ServerConstants.PLATINUM)) {
			errorMsg = "Subsription type not allowed. It should be either silver or gold or platinum";
		}
		
		// Redirect to the web page for token creation in any cases (error or not)
		RequestDispatcher rd = getServletContext().getRequestDispatcher("/createTokens.html");
		PrintWriter out= response.getWriter();
		if(errorMsg != null) {
			out.println("<font color=red>"+errorMsg+"</font>");
			rd.include(request, response);
		}else {
			// Generate the tokenID
			rnd = new Random();
			tokNum = Integer.toString(rnd.nextInt(0X1000000), 16);
			tokenID = "T" + tokNum;
			
			// Set other application specific data
			holder = "DAS";
			if(subType.equals(ServerConstants.SILVER)) {
				cost = ServerConstants.SILVER_COST;
				validityInterval = ServerConstants.SILVER_PERIOD;
			}else if(subType.equals(ServerConstants.GOLD)) {
				cost = ServerConstants.GOLD_COST;
				validityInterval = ServerConstants.GOLD_PERIOD;
			}else if(subType.equals(ServerConstants.PLATINUM)) {
				cost = ServerConstants.PLATINUM_COST;
				validityInterval = ServerConstants.PLATINUM_PERIOD;
			}

			// Insert data in the database
			Connection conn = (Connection) getServletContext().getAttribute("DBConnection");
			String sql = "INSERT INTO ACCESS_TOKEN" +
					"(token_id, holder, token_name, permission, sub_type, cost, validity_interval) VALUES" +
					"(?, ?, ?, ?, ?, ?, ?)";
			try {
				PreparedStatement pstmt = conn.prepareStatement(sql);
				pstmt.setString(1, tokenID);
				pstmt.setString(2, holder);
				pstmt.setString(3, resources);
				pstmt.setInt(4, Integer.parseInt(permission));
				pstmt.setString(5, subType);
				pstmt.setInt(6, cost);
				pstmt.setInt(7, validityInterval);
				pstmt.executeUpdate();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			out.println("<font color=green>Successful creation of access token</font>");
			rd.include(request, response);
		}
	}

}
