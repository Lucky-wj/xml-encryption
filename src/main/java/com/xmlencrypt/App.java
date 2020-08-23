package com.xmlencrypt;

import java.io.InputStream;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        InputStream resourceAsStream = XmlEncryptDecrptHandler.class.getResourceAsStream("/server.crt");
        System.out.println(resourceAsStream);
        System.out.println( "Hello World!" );
    }
}
