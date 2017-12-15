package jcifs.smb;

import java.security.Key;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;

import jcifs.Config;

/**
 * This class implements SmbExtendedAuthenticator interface to provide Kerberos
 * authentication feature via the Platform GSS.
 * 
 * @author kilokahn
 *
 */
public class Kerb5PlatformGssAuthenticator implements SmbExtendedAuthenticator{
    /**
     * This variable represents the FLAGS2 field in SMB Header block. The value
     * is predefined to support KerberosV5 authentication. In order to use
     * KerberosV5 authentication, user need to set the <code>Config</code> property
     * "jcifs.smb.client.flags2" as this value. For example:
     * <blockquote><pre>
     * Config.setProperty("jcifs.smb.client.flags2",Kerb5PlatformGssAuthenticator.FLAGS2);
     * </pre></blockquote>
     */
    public static final String FLAGS2 = "" + 0xd805;

    /**
     * This variable represents the CAPABILITIES field in SMB_PARAMETERS block.
     * The value is predefined to support KerberosV5 authentication. In order
     * to use KerberosV5 authentication, user need to set the <code>Config</code>
     * property "jcifs.smb.client.capabilities" as this value. For example:
     * <blockquote><pre>
     * Config.setProperty("jcifs.smb.client.capabilities",Kerb5PlatformGssAuthenticator.CAPABILITIES);
     * </pre></blockquote>
     */
    public static final String CAPABILITIES = "" + 0x800000d4;

    private static final String SERVICE = "cifs";

    private int userLifetime = GSSCredential.DEFAULT_LIFETIME;
    private int contextLifetime = GSSContext.DEFAULT_LIFETIME;

    /**
     * Get lifetime of current user.
     * 
     * @return the remaining lifetime in seconds. If the default lifetime is 
     * used, this value have no meaning.
     *         
     */
    public int getUserLifeTime(){
        return userLifetime;
    }

    /**
     * Set lifetime of current user.
     * 
     * @param time the lifetime in seconds
     *              
     */
    public void setUserLifeTime(int time){
        userLifetime = time;
    }

    /**
     * Get lifetime of this context. 
     *  
     * @return the remaining lifetime in seconds. If the default lifetime is 
     * used, this value have no meaning.
     */
    public int getLifeTime(){
        return contextLifetime;
    }

    /**
     * Set the lifetime for this context.
     * 
     * @param time the lifetime in seconds
     */
    public void setLifeTime(int time){
        contextLifetime = time;
    }

    @Override
    public void sessionSetup(
            final SmbSession session, 
            final ServerMessageBlock andx, 
            final ServerMessageBlock andxResponse) throws SmbException {
        setup(session, andx, andxResponse);
    }

    private void setup(SmbSession session, ServerMessageBlock andx, ServerMessageBlock andxResponse) throws SmbException {
        Kerb5Context context = null;
        try {
            String host = session.transport.address.getHostAddress();
            try {
                // Override with canonical name if available
                host = session.transport.address.getHostName();
            } catch(Exception e){
                // Okay to skip this
            }
            context = createContext(host);
            SpnegoContext spnego = new SpnegoContext(context.getGSSContext());

            byte[] token = new byte[0];

            Kerb5SessionSetupAndX request = null;
            Kerb5SessionSetupAndXResponse response = null;

            while (!spnego.isEstablished()) {
                token = spnego.initSecContext(token, 0, token.length);
                if(token != null) {
                    request = new Kerb5SessionSetupAndX(session, null);
                    request.getSecurityBlob().set(token);
                    response = new Kerb5SessionSetupAndXResponse(andxResponse);

                }
                session.transport.send(request, response);
                session.transport.digest = request.digest;

                token = response.getSecurityBlob().get();
            }
            session.setUid(response.uid);
            session.setSessionSetup(true);

        } catch (GSSException e) {
            throw new SmbException(e.getMessage());
        } finally {
            if(context != null) {
                try {
                    context.dispose();
                } catch (GSSException e) {

                }
            }
        }
    }
    private Kerb5Context createContext(String host) throws GSSException{
        Kerb5Context kerb5Context = 
            new Kerb5Context(
                host, 
                SERVICE,
                null,
                userLifetime,
                contextLifetime
                );
//        kerb5Context.getGSSContext().requestAnonymity(false);
//        kerb5Context.getGSSContext().requestSequenceDet(false);
//        kerb5Context.getGSSContext().requestMutualAuth(false);
//        kerb5Context.getGSSContext().requestConf(false);
//        kerb5Context.getGSSContext().requestInteg(false);
//        kerb5Context.getGSSContext().requestReplayDet(false);

        kerb5Context.getGSSContext().requestMutualAuth(true);
        return kerb5Context;
    }

    public String getDomain() {
        return getDefaultDomain();
	}
	private String getDefaultDomain(){
        return Config.getProperty("jcifs.smb.client.domain", "?");
	}

}
