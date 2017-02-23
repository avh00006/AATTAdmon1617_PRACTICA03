/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.*;
import java.lang.System.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * La clase ObtenerDatos implementa cuatro métodos públicos que permiten obtener
 * determinados datos de los certificados de tarjetas DNIe, Izenpe y Ona.
 *
 * @author tbc
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

    public String LeerNIF() {
        String nif = null;
        try {
            Card c = ConexionTarjeta();
            if (c == null) {
                throw new Exception("No se ha encontrado ninguna tarjeta");
            }
            byte[] atr = c.getATR().getBytes();
            CardChannel ch = c.getBasicChannel();

            if (esDNIe(atr)) {
                nif = leerDeCertificado(ch);
            }
            c.disconnect(false);

        } catch (Exception ex) {
            Logger.getLogger(ObtenerDatos.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        return nif;
    }

    public String escribirCertificado(String filename) {
        String nif = null;
        byte[] data = null;
        try {
            Card c = ConexionTarjeta();
            if (c == null) {
                throw new Exception("No se ha encontrado ninguna tarjeta");
            }
            byte[] atr = c.getATR().getBytes();
            CardChannel ch = c.getBasicChannel();

            if (esDNIe(atr)) {
                data = certificadoAFichero(ch, filename);
            }
            c.disconnect(false);

            if (data != null) {
                for (int i = 0; i < data.length; i++) {
                    System.out.print(String.format("%2X", data[i]));
                }
            }

        } catch (Exception ex) {
            Logger.getLogger(ObtenerDatos.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        return nif;
    }

    public String leerDeCertificado(CardChannel ch) throws CardException {
        int offset = 0;
        String completName = null;

        byte[] command = new byte[]{(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0x4D, (byte) 0x61, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x2E, (byte) 0x46, (byte) 0x69, (byte) 0x6C, (byte) 0x65};
        ResponseAPDU r = ch.transmit(new CommandAPDU(command));
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("SW incorrecto");
            return null;
        }

        //Seleccionamos el directorio PKCS#15 5015
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x50, (byte) 0x15};
        r = ch.transmit(new CommandAPDU(command));

        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("SW incorrecto");
            return null;
        }

        //Seleccionamos el Certificate Directory File (CDF) del DNIe 6004
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x60, (byte) 0x04};
        r = ch.transmit(new CommandAPDU(command));

        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("SW incorrecto");
            return null;
        }

        //Leemos FF bytes del archivo
        command = new byte[]{(byte) 0x00, (byte) 0xB0, (byte) 0x00, (byte) 0x00, (byte) 0xFF};
        r = ch.transmit(new CommandAPDU(command));

        if ((byte) r.getSW() == (byte) 0x9000) {
            byte[] r2 = r.getData();

            if (r2[4] == 0x30) {
                offset = 4;
                offset += r2[offset + 1] + 2; //Obviamos la seccion del Label
            }

            if (r2[offset] == 0x30) {
                offset += r2[offset + 1] + 2; //Obviamos la seccion de la informacion sobre la fecha de expedición etc
            }

            if ((byte) r2[offset] == (byte) 0xA1) {
                //El certificado empieza aquí
                byte[] r3 = new byte[9];

                
                
                
                //Nos posicionamos en el byte donde empieza el NIF y leemos sus 9 bytes
                for (int z = 0; z < 9; z++) {
                    r3[z] = r2[109 + z];
                }
                completName = new String(r3);
            }
        }
        return completName;
    }

    /** SOLUCION
     * Leer el certifcado y lo graba en un fichero
     *
     * @param ch
     * @param filename
     * @return El array de bytes leídos
     * @throws CardException
     */
    public byte[] certificadoAFichero(CardChannel ch, String filename) throws CardException {
        try {
            int offset = 0;
            String completName = null;
            byte[] data = null;

            byte[] command = new byte[]{(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0x4D, (byte) 0x61, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x2E, (byte) 0x46, (byte) 0x69, (byte) 0x6C, (byte) 0x65};
            ResponseAPDU r = ch.transmit(new CommandAPDU(command));
            if ((byte) r.getSW() != (byte) 0x9000) {
                System.out.println("SW incorrecto");
                return null;
            }

            //Seleccionamos el directorio PKCS#15 5015
            command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x50, (byte) 0x15};
            r = ch.transmit(new CommandAPDU(command));

            if ((byte) r.getSW() != (byte) 0x9000) {
                System.out.println("SW incorrecto");
                return null;
            }

            //Seleccionamos el Certificate Directory File (CDF) del DNIe 6004
            command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x60, (byte) 0x04};
            r = ch.transmit(new CommandAPDU(command));

            if ((byte) r.getSW() != (byte) 0x9000) {
                System.out.println("SW incorrecto");
                return null;
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] r2 = null;
            int bloque = 0;
            int seq = 0;
            do {
                //Leemos FF bytes del archivo
                command = new byte[]{(byte) 0x00, (byte) 0xB0, (byte) bloque, (byte) 0xff, (byte) 0xFF};
                r = ch.transmit(new CommandAPDU(command));

                System.out.println("Response SW1=" + String.format("%X", r.getSW1()) + " SW2=" + String.format("%X", r.getSW2()));
                if ((byte) r.getSW() == (byte) 0x9000) {
                    r2 = r.getData();

                    baos.write(r2, 0, r2.length);

                    for (int i = 0; i < r2.length; i++) {
                        byte[] t = new byte[1];
                        t[0] = r2[i];
                        System.out.println(i + (0xff * bloque) + String.format(" %2X", r2[i]) + " " + new String(t));
                    }
                    bloque++;
                } else {
                    return null;
                }

            } while (r2.length >= 0xfe);



            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            // certificate factory can now create the certificate 
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(bais);
            System.out.println("Subject DN" + cert.getSubjectDN());

            byte cer2[] = baos.toByteArray();

            int n = 1;
            
            do {
                offset=0;
                if (cer2[n] > 128) {
                    do {
                        offset=offset+cer2[n]-128;
                        n++;
                    } while (cer2[n] < 128);
                    offset=offset+cer2[n];
                    System.out.println("Longitud: "+offset);
                    n=cer2[offset];       
                }
                else
                {
                    System.out.println("Longitud: "+cer2[n]);
                
                n=cer2[n];                
                }



            } while (n < cer2.length);

            if (baos != null) {
                r2 = baos.toByteArray();
                try {
                    baos.close();
                } catch (IOException ex) {
                    Logger.getLogger(ObtenerDatos.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            return r2;
        } catch (CertificateException ex) {
            Logger.getLogger(ObtenerDatos.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;

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
}
