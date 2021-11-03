package thirdPartyServer;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Servlet implementation class DynamicAuth port
 */
@WebServlet("/DynamicAuth")
public class DynamicAuth extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	/* Credentials for the device's owner */
	private final String userID = "admin";
	private final String password = "admin";
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public DynamicAuth() {
        super();
        // TODO Auto-generated constructor stub
    }

    /**
     * Initialize the database by creating the ACCESS_TOKEN table
     */
    public void init() throws ServletException {
    	
    	Connection conn = (Connection) getServletContext().getAttribute("DBConnection");
    	try {
    		// Check if ACCESS-TOKEN table exist, if not, create a new table
    		DatabaseMetaData dbm = conn.getMetaData();
    		ResultSet rs = dbm.getTables(null, null, "ACCESS_TOKEN", null);
    		if (rs.next()) {
    			System.out.println("Table ACCESS-TOKEN already exists in the database");
    		}else {
    			System.out.println("Creating ACCESS-TOKEN table in the database...");
    			Statement stmt = conn.createStatement();
    			String sql = "CREATE TABLE ACCESS_TOKEN " +
    					"(id INTEGER AUTO_INCREMENT, " +
    					" token_id VARCHAR(10), " + 
    					" issuer VARCHAR(20), " + 
    					" holder VARCHAR(20), " +
    					" not_before DATE, " +
    					" not_after DATE, " +
    					" token_name VARCHAR(20), " +
    					" audience VARCHAR(40), " +
    					" permission INTEGER, " +
    					" sub_type VARCHAR(20), " +
    					" cost INTEGER, " +
    					" validity_interval INTEGER, " +
    					" PRIMARY KEY ( id ))";
    			stmt.executeUpdate(sql);
    		}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

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
		String user = request.getParameter("username");
		String pwd = request.getParameter("password");
		
		if(userID.equals(user) && pwd.equals(password)) {
			response.sendRedirect("createTokens.html");
		}else {
			RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
			PrintWriter out= response.getWriter();
			out.println("<font color=red>Either user name or password is wrong.</font>");
			rd.include(request, response);
		}
	}

}
