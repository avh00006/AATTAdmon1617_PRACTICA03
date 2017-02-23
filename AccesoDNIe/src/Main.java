import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;


/**
 * Aplicaciones Telemáticas para la Administración
 * 
 * Este programa debe
 * @author Juan Carlos Cuevas Martínez
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
        ByteArrayInputStream bais=null;
        
        //PUNTO 2. Conseguir que el método LeerNIF de ObtenerDatos devuelva el 
        //         correctamente NIF 
        ObtenerDatos od = new ObtenerDatos();
        String nif = od.LeerNIF();
        System.out.println("NIF: "+nif);
        
        //PUNTO 3. AUTENTICAR EL CLIENTE CON EL SERVIDOR
    }

    
 
    public static byte[] read(String aInputFileName){
 
    File file = new File(aInputFileName);
   
    byte[] result = new byte[(int)file.length()];
    try {
      InputStream input = null;
      try {
        int totalBytesRead = 0;
        input = new BufferedInputStream(new FileInputStream(file));
        while(totalBytesRead < result.length){
          int bytesRemaining = result.length - totalBytesRead;
          //input.read() returns -1, 0, or more :
          int bytesRead = input.read(result, totalBytesRead, bytesRemaining); 
          if (bytesRead > 0){
            totalBytesRead = totalBytesRead + bytesRead;
          }
        }
        /*
         the above style is a bit tricky: it places bytes into the 'result' array; 
         'result' is an output parameter;
         the while loop usually has a single iteration only.
        */
        for (int i = 0; i < result.length; i++) {
                    byte[] t = new byte[1];
                    t[0] = result[i];
                    System.out.println(i + String.format(" %2X", result[i]) + " " + new String(t));
                }
      
      }
      finally {
        
        input.close();
      }
    }
    catch (FileNotFoundException ex) {
      
    }
    catch (IOException ex) {
      
    }
    return result;
  }
}
