package thirdPartyServer.util;

public class ServerConstants {

	// Key Ks
	public static final String Ks = "taokhoaks123456789";
	
	// The size of all the random number used in the cryptographic system
	public static final int randomNumberSize = 32;
	
	// The size of the nonce used for the AES_256_CCM_8
	public static final int nonceSize = 12;
	
	// The holder name of the access tokens
	public static final String HOLDER = "DAS";
	
	// Subscription type
	public static final String SILVER = "silver";
	public static final String GOLD = "gold";
	public static final String PLATINUM = "platinum";
	
	// Cost of different subscriptions (euro)
	public static final int SILVER_COST = 10;
	public static final int GOLD_COST = 100;
	public static final int PLATINUM_COST = 500;
	
	// Duration period of different subscriptions (days)
	public static final int SILVER_PERIOD = 30;
	public static final int GOLD_PERIOD = 365;
	public static final int PLATINUM_PERIOD = 1825;
	
	// Permissions
	public static final int RETRIEVE = 32;
}
