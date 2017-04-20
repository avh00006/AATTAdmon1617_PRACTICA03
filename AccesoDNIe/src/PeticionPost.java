import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;

/**
 * La clase PeticionPost implementa la peticion POST al servidor y obtiene la respuesta
 *
 * @author Angel Venteo Heras
 */

public class PeticionPost {
private URL url;
String data;

public PeticionPost (String url) throws MalformedURLException{
this.url = new URL(url);
data="";
}

       /**
 * Metodo para codificar el usuario y la clave a enviar.
 * @param propiedad 
 * @param valor
 * @throws UnsupportedEncodingException
 */
public void add (String propiedad, String valor) throws UnsupportedEncodingException{
//codificamos cada uno de los valores
if (data.length()>0)
data+= "&"+ URLEncoder.encode(propiedad, "UTF-8")+ "=" +URLEncoder.encode(valor, "UTF-8");
else
data+= URLEncoder.encode(propiedad, "UTF-8")+ "=" +URLEncoder.encode(valor, "UTF-8");
}

    /**
 * Metodo para establecer la conexion y devolver la respuesta del servidor.
 * @return String respuesta
 * @throws IOException
 */

public String getRespueta() throws IOException {
String respuesta = "";
//abrimos la conexiÃ³n
URLConnection conn = url.openConnection();
//especificamos que vamos a escribir
conn.setDoOutput(true);
//obtenemos el flujo de escritura
OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
//escribimos
wr.write(data);
//cerramos la conexiÃ³n
  wr.close();

  //obtenemos el flujo de lectura
  BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
     String linea;
     //procesamos la salida
     while ((linea = rd.readLine()) != null) {
        respuesta+= linea;
     }
     
            String cadenaDondeBuscar = respuesta;
            String loQueQuieroBuscar = "Usuario autenticado correctamente!";
            String[] palabras = loQueQuieroBuscar.split("\\s+");
            for (String palabra : palabras) {
            if (cadenaDondeBuscar.contains(palabra)) {
            respuesta = ("Usuario autenticado correctamente!");
            
            }else{
             respuesta= ("Usuario incorrecto o no registrado!");
          }
}
          
return respuesta;
}

}

