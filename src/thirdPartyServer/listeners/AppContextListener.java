package thirdPartyServer.listeners;

import java.sql.Connection;
import java.sql.SQLException;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import thirdPartyServer.DBManager.DBConnectionManager;
import thirdPartyServer.ECCsecurity.EllipticCurveCryptography;

/**
 * Application Lifecycle Listener implementation class AppContextListener
 *
 */
@WebListener
public class AppContextListener implements ServletContextListener {

    /**
     * Default constructor. 
     */
    public AppContextListener() {
        // TODO Auto-generated constructor stub
    }

	/**
     * @see ServletContextListener#contextDestroyed(ServletContextEvent)
     */
    public void contextDestroyed(ServletContextEvent servletContextEvent)  { 
    	Connection con = (Connection) servletContextEvent.getServletContext().getAttribute("DBConnection");
    	try {
			con.close();
		} catch (SQLException e) {
			e.printStackTrace();
		}
    }

	/**
     * @see ServletContextListener#contextInitialized(ServletContextEvent)
     */
    public void contextInitialized(ServletContextEvent servletContextEvent)  { 
    	ServletContext ctx = servletContextEvent.getServletContext();

    	//initialize DB Connection
    	String dbURL = ctx.getInitParameter("dbURL");
    	String user = ctx.getInitParameter("dbUser");
    	String pwd = ctx.getInitParameter("dbPassword");

    	try {
    		DBConnectionManager connectionManager = new DBConnectionManager(dbURL, user, pwd);
    		ctx.setAttribute("DBConnection", connectionManager.getConnection());
    		System.out.println("DB Connection initialized successfully.");
    	} catch (ClassNotFoundException e) {
    		e.printStackTrace();
    	} catch (SQLException e) {
    		e.printStackTrace();
    	}
    	
    	// Create the private and public key using the elliptic curve secp256r1
    	System.out.println("Creation EC key pair");
    	EllipticCurveCryptography.createECKeyPair();
    }
	
}
