package com.dalogin.utils;

import org.apache.log4j.Logger;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;

public class PropertyUtils {
    /**
     *
     */
    private static Properties p = new Properties();
    /**
     *
     */
    private static Logger log = Logger.getLogger(Logger.class.getName());

    /**
     * Loads the property file on the context from the resource path.
     * According to the standard maven project folder layout it is the "../src/main/resources".
     *
     * @param propertyFileName
     * @param context
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static void loadPropertyFile(String propertyFileName, BufferedReader br) throws FileNotFoundException, IOException {
        //InputStream is = new FileInputStream(new File(propertyFileName));
        //DataInputStream in = new DataInputStream(is);
        //BufferedReader br = new BufferedReader(new InputStreamReader(in));
        p.load(br);
        log.info(propertyFileName + " is loaded.");
        br.close();
    }

    /**
     * Returns the property value by its key.
     *
     * @param propertyKey
     * @return
     * @throws Exception
     */
    public static String getProperty(String propertyKey) throws Exception {
        String propertyValue = p.getProperty(propertyKey.trim());
        try {
            propertyValue.trim();
        } catch (Exception e) {
            log.info("The property value for the key " + propertyKey + " is missing!");
        }
        return propertyValue.trim();
    }

    /**
     * @param propertyKey
     * @param value
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static void setProperty(String propertyKey, String value) throws FileNotFoundException, IOException {
        p.setProperty(propertyKey, value);
    }

    /**
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static void listProperties() throws FileNotFoundException, IOException {
        for (Enumeration<?> e = p.propertyNames(); e.hasMoreElements(); )
            while (e.hasMoreElements()) {
                String propertyKey = (String) e.nextElement();
                log.info(propertyKey + " -- " + p.getProperty(propertyKey));
            }
    }
}
