package com.dalogin.utils;

import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class jsonParser {
    private static final Logger log = Logger.getLogger(Logger.class.getName());

    public static void main(String[] args) throws Exception {
        String dbDriverClass = PropertyUtils.getProperty("dbDriverClass");
        String dbUrl = PropertyUtils.getProperty("dbUrl");
        String dbUserName = PropertyUtils.getProperty("dbUserName");
        String dbPassWord = PropertyUtils.getProperty("dbPassWord");
        Connection connect = null;
        try {
            // This will load the MySQL driver, each DB has its own driver
            Class.forName(dbDriverClass);
            // Setup the connection with the DB
            connect = DriverManager.getConnection(dbUrl, dbUserName, dbPassWord);
            connect.setAutoCommit(true);
            System.out.println("MySql connection is " + connect.isValid(3000));
            File f = new File("/Users/georgegaspar/Downloads/movie_theaters.json");
            if (f.exists()) {
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f));
                BufferedReader br = new BufferedReader(new InputStreamReader(bis));
                StringBuilder sb = new StringBuilder();
                String str;
                while ((str = br.readLine()) != null) {
                    sb.append(str);
                }
                JSONObject jObj_ = new JSONObject(sb.toString());
                JSONArray companyList = (JSONArray) jObj_.get("results");
                List<String> list = new ArrayList<>();
                List<String> insertedLocations = new ArrayList<>();
                for (int i = 0; i < companyList.length(); i++) {
                    JSONObject jObj = new JSONObject(companyList.get(i).toString());
                    String address = jObj.getString("formatted_address");
                    String name = jObj.getString("name");
                    JSONObject value3 = jObj.getJSONObject("geometry");
                    JSONObject value4 = value3.getJSONObject("location");
                    double lng = value4.getDouble("lng");
                    double lat = value4.getDouble("lat");
                    if (!address.isEmpty() && !name.isEmpty() && lng != 0 && lat != 0) {
                        try (PreparedStatement pstmt = connect.prepareStatement("select name from book.location")) {
                            ResultSet rs = pstmt.executeQuery();
                            while (rs.next()) {
                                String existingName = rs.getString("name");
                                list.add(existingName);
                            }
                        }
                        if (!list.contains(name)) {
                            insertedLocations.add(name);
                            String sqltestrun = "insert into book.location (locationId, formatted_address, name, latitude, longitude) values (default, ?, ?, ?, ?)";
                            try (PreparedStatement pstmt = connect.prepareStatement(sqltestrun)) {
                                pstmt.setString(1, address);
                                pstmt.setString(2, name);
                                pstmt.setDouble(3, lat);
                                pstmt.setDouble(4, lng);
                                pstmt.executeUpdate();
                            }
                        }
                    }
                }
                br.close();
            }
        } catch (Exception e) {
            log.info(e.getMessage());
        } finally {
            try {
                if (connect != null) connect.close();
            } catch (SQLException e) {
                log.info(e.getMessage());
            }
        }
    }
}
