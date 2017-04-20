import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.*;

/**
 * La clase ObtenerDatos implementa cuatro métodos públicos que permiten obtener
 * determinados datos de los certificados de tarjetas DNIe, Izenpe y Ona.
 *
 * @author Angel Venteo Heras
 */
public class ObtenerDatos {

    private static final byte[] dnie_v_1_0_Atr = {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x44,
        (byte) 0x4E, (byte) 0x49, (byte) 0x65, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00};
    private static final byte[] dnie_v_1_0_Mask = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF};

    public ObtenerDatos() {
    }
        /**
 * Metodo para obtener los datos de la zona publica a traves del certificado.
 * @return Usuario
 */
     public Usuario LeerNIF() {

        Usuario user = null;
        byte[] datos=null;
        try {
            Card c = ConexionTarjeta();
            if (c == null) {
                throw new Exception("ACCESO DNIe: No se ha encontrado ninguna tarjeta");
            }
            byte[] atr = c.getATR().getBytes();
            CardChannel ch = c.getBasicChannel();

            if (esDNIe(atr)) {
                datos = leerCertificado(ch);
                if(datos!=null)
                    user = leerDatosUsuario(datos);
            }
            c.disconnect(false);

        } catch (Exception ex) {
            Logger.getLogger(ObtenerDatos.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        return user;
    }

     /**
 * Metodo para leer el certificado y obtiene los datos públicos del DNIe.
 * @param ch
 * @return Objeto toByteArray con los datos
 * @throws CardException
 */
     
    public byte[] leerCertificado(CardChannel ch) throws CardException, CertificateException {


        int offset = 0;
        String completName = null;

        //[1] PRÃCTICA 3. Punto 1.a
        //El siguiente es el comando Select, permite la seleccion de un fichero dedicado (DF) o de un elemental (EF)
        //En este caso se trata de la seleccion directa de un fichero dedicado por nombre PKCS-15
        
        byte[] command = new byte[]{(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0x4D, (byte) 0x61, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x2E, (byte) 0x46, (byte) 0x69, (byte) 0x6C, (byte) 0x65};
        ResponseAPDU r = ch.transmit(new CommandAPDU(command));
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        //[2] PRÃCTICA 3. Punto 1.a
        //El siguiente es el comando Select, permite la seleccion de un fichero dedicado (DF) o de un elemental (EF)
        //En este caso se trata de la seleccion de un fichero elemental con Id: 50 15
        
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x50, (byte) 0x15};
        r = ch.transmit(new CommandAPDU(command));

        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        //[3] PRÃCTICA 3. Punto 1.a
        //El siguiente es el comando Select, permite la seleccion de un fichero dedicado (DF) o de un elemental (EF)
        //En este caso se trata de la seleccion de un fichero elemental con Id: 60 04
        
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x60, (byte) 0x04};
        r = ch.transmit(new CommandAPDU(command));

        byte[] responseData = null;
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        } else {
            responseData = r.getData();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] r2 = null;
        int bloque = 0;

        do {
             //[4] PRÃCTICA 3. Punto 1.b
            final byte CLA = (byte) 0x00;//Buscar qué valor poner aquí (0xFF no es el correcto) Comando Read Binary
            final byte INS = (byte) 0xB0;//Buscar qué valor poner aquí (0xFF no es el correcto) Comando Read Binary
            final byte LE = (byte) 0xFF;// Identificar qué significa este valor.  Número de bytes a leer, para este caso son 256

            //[4] PRÃCTICA 3. Punto 1.b
            command = new byte[]{CLA, INS, (byte) bloque/*P1*/, (byte) 0x00/*P2*/, LE};//Identificar qué hacen P1 y P2  Offset del primer byte a leer desde el
            //principio del fichero.
            r = ch.transmit(new CommandAPDU(command));

            //System.out.println("ACCESO DNIe: Response SW1=" + String.format("%X", r.getSW1()) + " SW2=" + String.format("%X", r.getSW2()));

            if ((byte) r.getSW() == (byte) 0x9000) {
                r2 = r.getData();

                baos.write(r2, 0, r2.length);

                for (int i = 0; i < r2.length; i++) {
                    byte[] t = new byte[1];
                    t[0] = r2[i];
                    System.out.println(i + (0xff * bloque) + String.format(" %2X", r2[i]) + " " + String.format(" %d", r2[i])+" "+new String(t));
                }
                bloque++;
            } else {
                return null;
            }

        } while (r2.length >= 0xfe);


         ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

      

        
        return baos.toByteArray();
    }

    
    
    
    /**
     * Este método establece la conexión con la tarjeta. La función busca el
     * Terminal que contenga una tarjeta, independientemente del tipo de tarjeta
     * que sea.
     *
     * @return objeto Card con conexión establecida
     * @throws Exception
     */
    private Card ConexionTarjeta() throws Exception {

        Card card = null;
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        //System.out.println("Terminals: " + terminals);

        for (int i = 0; i < terminals.size(); i++) {

            // get terminal
            CardTerminal terminal = terminals.get(i);

            try {
                if (terminal.isCardPresent()) {
                    card = terminal.connect("*"); //T=0, T=1 or T=CL(not needed)
                }
            } catch (Exception e) {

                System.out.println("Exception catched: " + e.getMessage());
                card = null;
            }
        }
        return card;
    }

    /**
     * Este método nos permite saber el tipo de tarjeta que estamos leyendo del
     * Terminal, a partir del ATR de ésta.
     *
     * @param atrCard ATR de la tarjeta que estamos leyendo
     * @return tipo de la tarjeta. 1 si es DNIe, 2 si es Starcos y 0 para los
     * demás tipos
     */
    private boolean esDNIe(byte[] atrCard) {
        int j = 0;
        boolean found = false;

        //Es una tarjeta DNIe?
        if (atrCard.length == dnie_v_1_0_Atr.length) {
            found = true;
            while (j < dnie_v_1_0_Atr.length && found) {
                if ((atrCard[j] & dnie_v_1_0_Mask[j]) != (dnie_v_1_0_Atr[j] & dnie_v_1_0_Mask[j])) {
                    found = false; //No es una tarjeta DNIe
                }
                j++;
            }
        }

        if (found == true) {
            return true;
        } else {
            return false;
        }

    }

    /**
     * Analiza los datos leídos del DNIe para obtener
     *   - nombre
     *   - apellidos
     *   - NIF
     *   - Nombre de usuario
     * @param datos
     * @return Objeto de la clase usuario
     */
    private Usuario leerDatosUsuario(byte[] datos) {
        
       String nombre;
   
        byte[] b = new byte[9];
        byte[] k = new byte[100];
           
        
        boolean parada=false;
        boolean parada2=false;
        
        for (int i=0;i<datos.length-3;i++){
            
            if(datos[i]==85 && datos[i+1]==4 && datos[i+2]==5){
                int n=0;
                for (int v=i+5;v<i+14;v++){
                    
                    b[n]=datos[v];
                    n++;
                
                }
            }
            if(parada==false){
            if(datos[i]==85 && datos[i+1]==4 && datos[i+2]==3 ){
                int n=0;
                for (int l=i+5;l<i+100;l++){
                    if(datos[l]==40){
                        parada2=true;
                    }
                    if(parada2==false){
                    k[n]=datos[l];
                    n++;
                    }
                }
                parada=true;
            }
            
            }
        }
        String a=new String (b);
        String z=new String (k);
        
        //Creamos el nombre de usuario

        String[] arrayNombre = z.split(" ");
        nombre = arrayNombre[2].substring(0, 1)+arrayNombre[0]+arrayNombre[1].substring(0, 1);      
       
        Usuario us = new Usuario();
        us.setNombre(arrayNombre[2]);
        us.setApellido1(arrayNombre[0]);
        us.setNif(a);
        us.setApellido2(arrayNombre[1]);
        
    return us;
    }
}
