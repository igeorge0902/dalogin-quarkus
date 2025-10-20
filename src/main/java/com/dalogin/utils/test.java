package com.dalogin.utils;

import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * @author Crunchify.com
 */
public class test {
    public final static int THREAD_POOL_SIZE = 5;
    private static final String SALT = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";
    private static final String IV = "F27D5C9927726BCEFE7510B1BDD3D137";
    private static final String activationToken_ = "G";
    private static final int KEYSIZE = 128;
    private static final int ITERATIONCOUNT = 1000;
    public static Map<String, Integer> crunchifyHashTableObject = null;
    public static Map<String, Integer> crunchifySynchronizedMapObject = null;
    private static boolean True;

    //spublic static Map<String, Integer> crunchifyConcurrentHashMapObject = null;
    public static void main(String[] args) throws InterruptedException, IOException, SQLException, ClassNotFoundException {
        AesUtil aesUtil = new AesUtil(KEYSIZE, ITERATIONCOUNT);
        String query_ = aesUtil.decrypt(SALT, IV, activationToken_, "0+/H2wuaUTwxrD/sJJ9jyWytNprm6BvqjSwCLj4KTtiWpxJjCIkhprk/SKVQ45v+");
        //  String split = query_.split("r=")[1];     
        String hmacHash = hmac512.getLoginHmac512("GG", "318672fb86ed60eb2a230a782d53f93c243d199f6f6972fee17a0ce8591ec803f0abf83335b2777b1c44792f98cf66567109c843a1c0deaa2a26b85825ca5ee7", "12345678", "1634743894", "188");
        System.out.println(hmacHash);
        //	String test = "aC8SRTzA1vhfFZr_bSjE2GmAj8wgHWHck7O1N1YM.gaspars-macbook-pro";
        //	System.out.println(test.split("\\.")[0].toString());
        Class.forName("com.mysql.cj.jdbc.Driver");
        Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306", "sqluser", "sqluserpw-1982");
        con.setCatalog("login");
        con.setAutoCommit(true);
        System.out.print("dB Connection created, catalog set to \"login\"");
        String[] params_ = query_.split("&");
        Map<String, String> queryMap = new HashMap<String, String>();
        String user = "";
        String token2 = "";
        int j = 0;
        Arrays.sort(params_);
        for (String param : params_) {
            String name = param.split("=")[0];
            String value = param.split("=")[1];
            queryMap.put(name, value);
            j++;
            if (j == 1) {
                token2 = value;
            }
            if (j == 2) {
                user = value;
            }
        }
        System.out.println(token2);
        System.out.println(user);
        File f = new File("/Users/georgegaspar/Downloads/test.json");
        if (f.exists() == true) {
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f));
            BufferedReader br_ = new BufferedReader(new InputStreamReader(bis));
            StringBuilder sb_ = new StringBuilder();
            String str_;
            while ((str_ = br_.readLine()) != null) {
                sb_.append(str_);
            }
            JSONObject jObj_ = new JSONObject(sb_.toString());
            JSONArray ticketsList = (JSONArray) jObj_.get("ticketIds");
            System.out.print("ticketId: " + ticketsList.get(0));
            List<Integer> ticketIds = new ArrayList<>();
            for (int i = 0; i < ticketsList.length(); i++) {
                int ticketId = Integer.valueOf(ticketsList.get(i).toString());
                ticketIds.add(ticketId);
            }
            System.out.println(ticketIds);
		    	/*
		    	String value = jObj.getString("formatted_address");
		        String value2 = jObj.getString("name");
		        JSONObject value3 = jObj.getJSONObject("geometry");
		        JSONObject value4 = value3.getJSONObject("location");
		        double lng = value4.getDouble("lng");
		        double lat = value4.getDouble("lat");
		        System.out.println(value);
		        System.out.println(value2);
		        System.out.println(lng);
		        System.out.println(lat);
		        */
            br_.close();
        }
        System.out.println(System.getProperty("user.dir"));
        //EmailValidator em = new EmailValidator();
        True = EmailValidator.validate("");
        System.out.println(String.valueOf(True));
        StringBuilder sb = new StringBuilder();
        String deviceId = "{\"name\":\"abc\",\"age\":\"21\"}";
        InputStream in_ = IOUtils.toInputStream(deviceId, "UTF-8");
        BufferedReader br = new BufferedReader(new InputStreamReader(in_));
        String str;
        while ((str = br.readLine()) != null) {
            sb.append(str);
        }
        JSONObject jObj = new JSONObject(sb.toString());
        JSONArray stats = jObj.names();
        //   String name_ = stats.getString(0);
        //   String value_ = jObj.getString("name");
        //   System.out.println(value_);
        for (int i = 0; i < stats.length(); i++) {
            String name = stats.getString(i);
            String value = jObj.getString(name);
            System.out.println(name);
            System.out.println(value);
            // JSONObject stat = jObj.getJSONObject(name);
            // stat.getInt("min");
            // stat.getInt("max");
        }
        String query = "A3-A2";
        String[] params = query.split("-");
        for (int i = 0; i < params.length; i++) {
            String value = params[i];
            System.out.println(value);
        }
		/*
		// Test with Hashtable Object
		crunchifyHashTableObject = new Hashtable<String, Integer>();
		crunchifyPerformTest(crunchifyHashTableObject);
		// Test with synchronizedMap Object
		crunchifySynchronizedMapObject = Collections.synchronizedMap(new HashMap<String, Integer>());
		crunchifyPerformTest(crunchifySynchronizedMapObject);
		// Test with ConcurrentHashMap Object
		Map<String, Integer> crunchifyConcurrentHashMapObject = new ConcurrentHashMap<String, Integer>();
		crunchifyPerformTest(crunchifyConcurrentHashMapObject);
		 */
    }

    public static void crunchifyPerformTest(final Map<String, Integer> crunchifyThreads) throws InterruptedException {
        System.out.println("Test started for: " + crunchifyThreads.getClass());
        long averageTime = 0;
        for (int i = 0; i < 5; i++) {
            long startTime = System.nanoTime();
            ExecutorService crunchifyExServer = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
            for (int j = 0; j < THREAD_POOL_SIZE; j++) {
                crunchifyExServer.execute(new Runnable() {
                    @SuppressWarnings("unused")
                    @Override
                    public void run() {
                        for (int i = 0; i < 500000; i++) {
                            Integer crunchifyRandomNumber = (int) Math.ceil(Math.random() * 550000);
                            // Retrieve value. We are not using it anywhere
                            Integer crunchifyValue = crunchifyThreads.get(String.valueOf(crunchifyRandomNumber));
                            // Put value
                            crunchifyThreads.put(String.valueOf(crunchifyRandomNumber), crunchifyRandomNumber);
                        }
                    }
                });
            }
            // Make sure executor stops
            crunchifyExServer.shutdown();
            // Blocks until all tasks have completed execution after a shutdown request
            crunchifyExServer.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
            long entTime = System.nanoTime();
            long totalTime = (entTime - startTime) / 1000000L;
            averageTime += totalTime;
            System.out.println("2500K entried added/retrieved in " + totalTime + " ms");
        }
        System.out.println("For " + crunchifyThreads.getClass() + " the average time is " + averageTime / 5 + " ms\n");
    }
}