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
 * Este programa debe ller el nombre y NIF de un usuario del DNIe, formar el identificador de usuario y autenticarse con un servidor remoto a través de HTTP 
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
        
        //TODO PUNTO 3. AUTENTICAR EL CLIENTE CON EL SERVIDOR
        
    }
}
