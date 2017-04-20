
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
 * Este programa debe leer el nombre y NIF de un usuario del DNIe, formar el identificador de usuario y autenticarse con un servidor remoto a través de HTTP 
 * @author Angel Venteo Heras
 */
public class Main {
    /**
     * Metodo principal donde creamos un objeto de la clase ObtenerDatos, obtenemos los datos, 
     *  se ejecuta el menu y se envía la petición al servidor mediante POST.
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
        
        
        ByteArrayInputStream bais=null;
        
        //TAREA 2. Conseguir que el método LeerNIF de ObtenerDatos devuelva el 
        //         correctamente los datos de usuario 
        ObtenerDatos od = new ObtenerDatos();
        
        //Saludo
         System.out.println("usuario: ") ;
        Usuario user = od.LeerNIF();
        
        System.out.println(" \r\n");
        System.out.println("IDENTIFICANDO...");
        System.out.println(" ");
        if(user!=null){
            System.out.println("Usuario Indentificado: "+user.toString());
            System.out.println(" ");
            String nombre=user.getNombre().substring(0, 1)+user.getApellido1()+user.getApellido2().substring(0, 1);
            System.out.println("AUTENTICANDO...\r\n");
            PeticionPost post = new PeticionPost ("http://localhost:82/phpproject/server_dni/Menu.php");
            post.add("nombre", nombre);
            post.add("password", user.getNif());
            String respuesta = post.getRespueta();
            System.out.println(respuesta);
            if (respuesta=="Usuario autenticado correctamente!"){
            System.out.println(" ");
            System.out.println("Bienvenido! \r\n");
            System.out.println("Datos de usuario: \r\n");
            System.out.println("Nombre: "+nombre);
            System.out.println("Contraseña: "+user.getNif());
            System.out.println(" ");
            System.out.println(" ");
            
            }
        }
        
        //TAREA 3. AUTENTICAR EL CLIENTE CON EL SERVIDOR
        
         
        
    }
}
