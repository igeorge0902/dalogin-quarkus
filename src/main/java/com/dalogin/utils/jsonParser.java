package com.dalogin.utils;

import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class jsonParser {
    private static Logger log = Logger.getLogger(Logger.class.getName());
    private static volatile String address;
    private static volatile String name;
    private static volatile double lat;
    private static volatile double lng;
    private static volatile String sqltestrun;
    private static Connection connect = null;
    private static PreparedStatement preparedStatement = null;

    public static void main(String[] args) throws Exception {
        String dbDriverClass = PropertyUtils.getProperty("dbDriverClass");
        String dbUrl = PropertyUtils.getProperty("dbUrl");
        String dbUserName = PropertyUtils.getProperty("dbUserName");
        String dbPassWord = PropertyUtils.getProperty("dbPassWord");
        try {
            // This will load the MySQL driver, each DB has its own driver
            Class.forName(dbDriverClass);
            // Setup the connection with the DB
            connect = DriverManager.getConnection(dbUrl, dbUserName, dbPassWord);
            connect.setAutoCommit(true);
            System.out.println("MySql connection is " + connect.isValid(3000));
            File f = new File("/Users/georgegaspar/Downloads/movie_theaters.json");
            if (f.exists() == true) {
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f));
                BufferedReader br = new BufferedReader(new InputStreamReader(bis));
                StringBuilder sb = new StringBuilder();
                String str;
                while ((str = br.readLine()) != null) {
                    sb.append(str);
                }
                JSONObject jObj_ = new JSONObject(sb.toString());
                JSONArray companyList = (JSONArray) jObj_.get("results");
                //  System.out.println(values);
                List<String> list = new ArrayList<>();
                List<String> insertedLocations = new ArrayList<>();
                for (int i = 0; i < companyList.length(); i++) {
                    JSONObject jObj = new JSONObject(companyList.get(i).toString());
                    address = jObj.getString("formatted_address");
                    name = jObj.getString("name");
                    JSONObject value3 = jObj.getJSONObject("geometry");
                    JSONObject value4 = value3.getJSONObject("location");
                    lng = value4.getDouble("lng");
                    lat = value4.getDouble("lat");
                    if (!address.isEmpty() && !name.isEmpty() && lng != 0 && lat != 0) {
                        preparedStatement = connect.prepareStatement("select name from book.location");
                        ResultSet rs = preparedStatement.executeQuery();
                        while (rs.next()) {
                            String name = rs.getString("name");
                            list.add(name);
                        }
                        if (!list.contains(name)) {
                            insertedLocations.add(name);
                            sqltestrun = "insert into book.location (locationId, formatted_address, name, latitude, longitude) values (default, ?, ?, ?, ?)";
                            preparedStatement = connect.prepareStatement(sqltestrun);
                            preparedStatement.setString(1, address);
                            preparedStatement.setString(2, name);
                            preparedStatement.setDouble(3, lat);
                            preparedStatement.setDouble(4, lng);
                            preparedStatement.executeUpdate();
                            preparedStatement.closeOnCompletion();
                        }
                    }
                }
                br.close();
            }
        } catch (Exception e) {
            log.info(e.getMessage());
            ;
        } finally {
            try {
                connect.close();
            } catch (SQLException e) {
                log.info(e.getMessage());
                ;
            }
        }
    }
}
