import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import jcifs.Config;
import jcifs.smb.Kerb5PlatformGssAuthenticator;
import jcifs.smb.SmbFile;

/**
 * Example to demonstrate the use of Platform GSS for credentials
 *
 * @author kilokahn
 */
public class KerberosPlatformGSSAuthExample {

    private static String URL = "";

    public static void main(String[] args) {
        if(args.length != 1){
            help();
            return;
        }
        URL = args[0];

        Config.setProperty("jcifs.smb.client.capabilities", Kerb5PlatformGssAuthenticator.CAPABILITIES);
        Config.setProperty("jcifs.smb.client.flags2",Kerb5PlatformGssAuthenticator.FLAGS2);
        try {
            // list file
            SmbFile dir = new SmbFile(URL, new Kerb5PlatformGssAuthenticator());
            SmbFile[] files = dir.listFiles();
            for (SmbFile file : files) {
                printFileDetails(file);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } 
    }

    private static void printFileDetails(SmbFile file) throws IOException {
        System.out.println("-->" + file.getName());
        System.out.println("File length -->" + file.length());
        StringBuilder result = new StringBuilder();
        String line;
        boolean flag = false;
        String newLine = System.getProperty("line.separator");
        BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()));
        while ((line = reader.readLine()) != null) {
            result.append(flag? newLine: "").append(line);
            flag = true;
        }
        System.out.println("File contents -->" + result.toString());
        System.out.println("DFS path: " + file.getDfsPath());
    }

    private static void help(){
        System.out.println("Add arguments in the order of:");
        System.out.println("[smb://url]");
    }
}
