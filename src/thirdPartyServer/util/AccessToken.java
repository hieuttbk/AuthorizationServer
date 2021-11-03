package thirdPartyServer.util;

import java.sql.Date;

public class AccessToken {

	private String tokenID;
	private int version;
	private String issuer;
	private String holder;
	private Date notBefore;
	private Date notAfter;
	private String tokenName;
	private String audience;
	private int permission;
	private int cost;
	private int validityInterval;
	
	public AccessToken(String tokID, int ver, String iss, String hold, Date notBef, Date notAft, String tokName,
			String aud, int perm, int c, int valInt) {
		tokenID = tokID;
		version = ver;
		issuer = iss;
		holder = hold;
		notBefore = notBef;
		notAfter = notAft;
		tokenName = tokName;
		audience = aud;
		permission = perm;
		cost = c;
		validityInterval = valInt;
	}
	
	public void setTokenID(String tokID) {
		tokenID = tokID;
	}
	
	public void setVersion(int ver) {
		version = ver;
	}
	
	public void setIssuer(String iss) {
		issuer = iss;
	}
	
	public void setHolder(String hold) {
		holder = hold;
	}
	
	public void setNotBefore(Date notBef) {
		notBefore = notBef;
	}
	
	public void setNotAfter(Date notAft) {
		notAfter = notAft;
	}
	
	public void setTokenName(String tokName) {
		tokenName = tokName;
	}
	
	public void setAudience(String aud) {
		audience = aud;
	}
	
	public void setPermission(int per) {
		permission = per;
	}
	
	public void setCost(int c) {
		cost = c;
	}
	
	public void setValidityInterval(int valInt) {
		validityInterval = valInt;
	}
	
	public String getTokenID() {
		return tokenID;
	}
	
	public int getVersion() {
		return version;
	}
	
	public String getIssuer() {
		return issuer;
	}
	
	public String getHolder() {
		return holder;
	}
	
	public Date getNotBefore() {
		return notBefore;
	}
	
	public Date getNotAfter() {
		return notAfter;
	}
	
	public String getTokenName() {
		return tokenName;
	}
	
	public String getAudience() {
		return audience;
	}
	
	public int getPermission() {
		return permission;
	}
	
	public int getCost() {
		return cost;
	}
	
	public int getValidityInterval() {
		return validityInterval;
	}
}
